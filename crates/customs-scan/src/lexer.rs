//! Hand-written lexers for Python, JavaScript and shell.
//!
//! The lexers are deliberately forgiving: they never fail, they only need to separate
//! identifiers, string literals, numbers and punctuation well enough that indicator rules can
//! tell code from comments and strings. A word like `subprocess` inside a comment produces no
//! token at all, and inside a string it produces a `Str` token, so token rules only ever see
//! real identifiers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    Js,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokKind {
    Ident,
    /// String literal content without quotes and without decoding escapes. A JavaScript
    /// template literal yields one `Str` per literal chunk around `${...}` interpolations.
    Str,
    Num,
    Punct,
    /// JavaScript regular expression literal (body only).
    Regex,
    /// Logical end of line (Python only, outside brackets). Used to delimit statements.
    Newline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    pub kind: TokKind,
    pub text: &'a str,
    /// 1-based line where the token starts.
    pub line: u32,
}

pub fn lex(src: &str, lang: Lang) -> Vec<Token<'_>> {
    match lang {
        Lang::Python => Lexer::new(src).python(),
        Lang::Js => Lexer::new(src).js(),
        Lang::Shell => Lexer::new(src).shell(),
    }
}

const PY_OPS: &[&str] = &[
    "**=", "//=", ">>=", "<<=", "...", "->", ":=", "**", "//", "==", "!=", "<=", ">=", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "@=",
];

const JS_OPS: &[&str] = &[
    ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=",
    "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "**", "<<", ">>",
];

/// Keywords after which a `/` starts a regular expression rather than a division.
const JS_REGEX_PRECEDERS: &[&str] = &[
    "return",
    "typeof",
    "case",
    "do",
    "else",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "instanceof",
    "yield",
    "await",
];

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

struct Lexer<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
    line: u32,
    out: Vec<Token<'a>>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            b: src.as_bytes(),
            i: 0,
            line: 1,
            out: Vec::with_capacity(src.len() / 4),
        }
    }

    fn peek(&self, off: usize) -> u8 {
        self.b.get(self.i + off).copied().unwrap_or(0)
    }

    fn push(&mut self, kind: TokKind, start: usize, end: usize, line: u32) {
        self.out.push(Token {
            kind,
            text: &self.src[start..end],
            line,
        });
    }

    /// Advance `i` to `end`, counting newlines in between.
    fn advance_to(&mut self, end: usize) {
        let end = end.min(self.b.len());
        self.line += self.b[self.i..end].iter().filter(|&&c| c == b'\n').count() as u32;
        self.i = end;
    }

    fn skip_to_eol(&mut self) {
        while self.i < self.b.len() && self.b[self.i] != b'\n' {
            self.i += 1;
        }
    }

    fn ident(&mut self) {
        let start = self.i;
        while self.i < self.b.len() && (is_ident_char(self.b[self.i]) || self.b[self.i] == b'$') {
            self.i += 1;
        }
        self.push(TokKind::Ident, start, self.i, self.line);
    }

    fn number(&mut self) {
        let start = self.i;
        let hex = self.peek(0) == b'0' && matches!(self.peek(1), b'x' | b'X');
        while self.i < self.b.len() {
            let c = self.b[self.i];
            let exponent_sign =
                (c == b'+' || c == b'-') && !hex && matches!(self.b[self.i - 1], b'e' | b'E');
            if !(c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || exponent_sign) {
                break;
            }
            self.i += 1;
        }
        self.push(TokKind::Num, start, self.i, self.line);
    }

    fn punct(&mut self, ops: &[&str]) {
        let rest = &self.b[self.i..];
        let len = ops
            .iter()
            .find(|op| rest.starts_with(op.as_bytes()))
            .map(|op| op.len())
            .unwrap_or(1);
        let start = self.i;
        self.i += len;
        self.push(TokKind::Punct, start, self.i, self.line);
    }

    /// Scan a single-line quoted string starting at the opening quote. Unterminated strings
    /// end at the newline so one stray quote cannot swallow the rest of the file.
    fn quoted(&mut self, quote: u8, escapes: bool) {
        let line = self.line;
        let start = self.i + 1;
        let mut j = start;
        let mut newlines = 0;
        while j < self.b.len() {
            let c = self.b[j];
            if c == b'\\' && escapes {
                if self.b.get(j + 1) == Some(&b'\n') {
                    newlines += 1;
                }
                j += 2;
                continue;
            }
            if c == quote || c == b'\n' {
                break;
            }
            j += 1;
        }
        let end = j.min(self.b.len());
        self.push(TokKind::Str, start, end, line);
        self.line += newlines;
        self.i = if end < self.b.len() && self.b[end] == quote {
            end + 1
        } else {
            end
        };
    }

    fn python(mut self) -> Vec<Token<'a>> {
        let mut depth: usize = 0;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            match c {
                b'#' => self.skip_to_eol(),
                b'\n' => {
                    if depth == 0 && self.out.last().is_some_and(|t| t.kind != TokKind::Newline) {
                        self.push(TokKind::Newline, self.i, self.i, self.line);
                    }
                    self.line += 1;
                    self.i += 1;
                }
                b'\\' if self.peek(1) == b'\n' => {
                    self.line += 1;
                    self.i += 2;
                }
                b'\\' if self.peek(1) == b'\r' && self.peek(2) == b'\n' => {
                    self.line += 1;
                    self.i += 3;
                }
                b'\'' | b'"' => self.py_string(c),
                b'0'..=b'9' => self.number(),
                b'.' if self.peek(1).is_ascii_digit() => self.number(),
                _ if is_ident_start(c) => self.ident(),
                _ if c.is_ascii_whitespace() => self.i += 1,
                _ => {
                    match c {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    self.punct(PY_OPS);
                }
            }
        }
        self.out
    }

    fn py_string(&mut self, quote: u8) {
        // A string prefix (r, b, f, rb, ...) was lexed as an identifier glued to the quote.
        if let Some(prev) = self.out.last() {
            let prev_end =
                prev.text.as_ptr() as usize - self.src.as_ptr() as usize + prev.text.len();
            let lower = prev.text.to_ascii_lowercase();
            if prev.kind == TokKind::Ident
                && prev_end == self.i
                && matches!(
                    lower.as_str(),
                    "r" | "u" | "b" | "f" | "t" | "br" | "rb" | "fr" | "rf" | "tr" | "rt"
                )
            {
                self.out.pop();
            }
        }
        let triple = self.peek(1) == quote && self.peek(2) == quote;
        if !triple {
            // Raw strings still cannot end on an escaped quote, so escapes are always honored.
            self.quoted(quote, true);
            return;
        }
        let line = self.line;
        let start = self.i + 3;
        let mut j = start;
        while j < self.b.len() {
            if self.b[j] == b'\\' {
                j += 2;
                continue;
            }
            if self.b[j] == quote
                && self.b.get(j + 1) == Some(&quote)
                && self.b.get(j + 2) == Some(&quote)
            {
                break;
            }
            j += 1;
        }
        let end = j.min(self.b.len());
        self.push(TokKind::Str, start, end, line);
        self.i = start;
        self.advance_to(end);
        self.i = (end + 3).min(self.b.len());
    }

    fn js_regex_allowed(&self) -> bool {
        match self.out.last() {
            None => true,
            Some(t) => match t.kind {
                TokKind::Num | TokKind::Str | TokKind::Regex => false,
                TokKind::Ident => JS_REGEX_PRECEDERS.contains(&t.text),
                TokKind::Punct => !matches!(t.text, ")" | "]" | "}"),
                TokKind::Newline => true,
            },
        }
    }

    /// Try to scan a regex literal at `/`. Returns false (consuming nothing) when the line
    /// ends before the closing slash, in which case the caller treats `/` as division.
    fn js_regex(&mut self) -> bool {
        let start = self.i + 1;
        let mut j = start;
        let mut in_class = false;
        while j < self.b.len() {
            match self.b[j] {
                b'\\' => j += 1,
                b'\n' => return false,
                b'[' => in_class = true,
                b']' => in_class = false,
                b'/' if !in_class => break,
                _ => {}
            }
            j += 1;
        }
        if j >= self.b.len() {
            return false;
        }
        self.push(TokKind::Regex, start, j, self.line);
        j += 1;
        while j < self.b.len() && self.b[j].is_ascii_alphabetic() {
            j += 1;
        }
        self.i = j;
        true
    }

    /// Scan a template literal chunk starting just after a backtick or a closing `}` of an
    /// interpolation. Returns true when the chunk ended at `${` (an interpolation opens).
    fn js_template_chunk(&mut self) -> bool {
        let line = self.line;
        let start = self.i;
        let mut j = start;
        while j < self.b.len() {
            match self.b[j] {
                b'\\' => {
                    j += 2;
                    continue;
                }
                b'`' => break,
                b'$' if self.b.get(j + 1) == Some(&b'{') => break,
                _ => {}
            }
            j += 1;
        }
        let end = j.min(self.b.len());
        self.push(TokKind::Str, start, end, line);
        self.advance_to(end);
        if end >= self.b.len() {
            return false;
        }
        if self.b[end] == b'`' {
            self.i = end + 1;
            false
        } else {
            self.i = end + 2;
            true
        }
    }

    fn js(mut self) -> Vec<Token<'a>> {
        // Brace depth and the depths at which template interpolations were opened, so a `}`
        // can resume the enclosing template literal.
        let mut braces: usize = 0;
        let mut templates: Vec<usize> = Vec::new();
        if self.src.starts_with("#!") {
            self.skip_to_eol();
        }
        while self.i < self.b.len() {
            let c = self.b[self.i];
            match c {
                b'\n' => {
                    self.line += 1;
                    self.i += 1;
                }
                b'/' if self.peek(1) == b'/' => self.skip_to_eol(),
                b'/' if self.peek(1) == b'*' => {
                    let end = self.src[self.i + 2..]
                        .find("*/")
                        .map(|p| self.i + 2 + p + 2)
                        .unwrap_or(self.b.len());
                    self.advance_to(end);
                }
                b'/' if self.js_regex_allowed() && self.js_regex() => {}
                b'\'' | b'"' => self.quoted(c, true),
                b'`' => {
                    self.i += 1;
                    if self.js_template_chunk() {
                        braces += 1;
                        templates.push(braces);
                    }
                }
                b'}' if templates.last() == Some(&braces) => {
                    templates.pop();
                    braces = braces.saturating_sub(1);
                    self.i += 1;
                    if self.js_template_chunk() {
                        braces += 1;
                        templates.push(braces);
                    }
                }
                b'0'..=b'9' => self.number(),
                b'.' if self.peek(1).is_ascii_digit() => self.number(),
                b'$' => self.ident(),
                _ if is_ident_start(c) => self.ident(),
                _ if c.is_ascii_whitespace() => self.i += 1,
                _ => {
                    match c {
                        b'{' => braces += 1,
                        b'}' => braces = braces.saturating_sub(1),
                        _ => {}
                    }
                    self.punct(JS_OPS);
                }
            }
        }
        self.out
    }

    fn shell(mut self) -> Vec<Token<'a>> {
        let mut line_start = true;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if line_start {
                // Batch file comments: `REM ...` and `:: ...` at the start of a line.
                let rest = &self.b[self.i..];
                let trimmed = rest
                    .iter()
                    .position(|&x| x != b' ' && x != b'\t' && x != b'@')
                    .unwrap_or(rest.len());
                let r = &rest[trimmed..];
                if r.starts_with(b"::")
                    || (r.len() >= 4
                        && r[..3].eq_ignore_ascii_case(b"rem")
                        && matches!(r[3], b' ' | b'\t' | b'\r' | b'\n'))
                {
                    self.skip_to_eol();
                    continue;
                }
                line_start = false;
            }
            match c {
                b'\n' => {
                    self.line += 1;
                    self.i += 1;
                    line_start = true;
                }
                b'#' => self.skip_to_eol(),
                b'<' if self.peek(1) == b'#' => {
                    // PowerShell block comment.
                    let end = self.src[self.i + 2..]
                        .find("#>")
                        .map(|p| self.i + 2 + p + 2)
                        .unwrap_or(self.b.len());
                    self.advance_to(end);
                }
                b'\'' => self.quoted(b'\'', false),
                b'"' => self.quoted(b'"', true),
                b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>' => {
                    let start = self.i;
                    let len = if self.peek(1) == c && c != b'(' && c != b')' {
                        2
                    } else {
                        1
                    };
                    self.i += len;
                    self.push(TokKind::Punct, start, self.i, self.line);
                }
                _ if c.is_ascii_whitespace() => self.i += 1,
                _ => {
                    let start = self.i;
                    while self.i < self.b.len() {
                        let d = self.b[self.i];
                        if d.is_ascii_whitespace()
                            || matches!(d, b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>')
                            || d == b'\''
                            || d == b'"'
                        {
                            break;
                        }
                        self.i += 1;
                    }
                    self.push(TokKind::Ident, start, self.i, self.line);
                }
            }
        }
        self.out
    }
}

/// Replace shell comments with spaces (keeping newlines and byte offsets) so regex rules
/// over the whole script do not match commented-out commands.
pub fn strip_shell_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        let trimmed = line.trim_start_matches([' ', '\t', '@']);
        let lower_head: String = trimmed.chars().take(4).collect::<String>().to_lowercase();
        let is_bat_comment = trimmed.starts_with("::")
            || (lower_head.starts_with("rem")
                && lower_head.chars().nth(3).is_none_or(|c| c.is_whitespace()));
        let cut = if is_bat_comment {
            Some(0)
        } else {
            shell_comment_start(line)
        };
        match cut {
            Some(pos) => {
                out.push_str(&line[..pos]);
                for ch in line[pos..].chars() {
                    if ch == '\n' {
                        out.push('\n');
                    } else {
                        // Pad with spaces of the same byte length to keep offsets stable.
                        for _ in 0..ch.len_utf8() {
                            out.push(' ');
                        }
                    }
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// Byte offset of a `#` comment on a shell line, ignoring `#` inside quotes and inside
/// words (such as `${#var}` or URL fragments).
fn shell_comment_start(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) => {
                if c == b'\\' && q == b'"' {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'\'' | b'"' => quote = Some(c),
                b'\\' => i += 1,
                b'#' if i == 0 || b[i - 1].is_ascii_whitespace() || b[i - 1] == b';' => {
                    return Some(i)
                }
                _ => {}
            },
        }
        i += 1;
    }
    None
}

/// Decode the escapes that spell characters by number (`\\x63`, `\\u0063`, `\\u{63}`,
/// Python's `\\U00000063`) in a string literal; `None` when there are none. Malware writes
/// module names, hosts and commands this way so that literal matching misses them.
/// Control characters stay escaped, so line numbers inside the literal do not move, and an
/// escaped backslash is never the start of an escape.
pub fn decode_escapes(s: &str) -> Option<String> {
    if !s.contains('\\') {
        return None;
    }
    let b = s.as_bytes();
    let hex = |from: usize, n: usize| -> Option<u32> {
        let h = s.get(from..from + n)?;
        h.bytes()
            .all(|c| c.is_ascii_hexdigit())
            .then(|| u32::from_str_radix(h, 16).ok())
            .flatten()
    };
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut i = 0;
    let mut copied = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            i += 1;
            continue;
        }
        let (code, len) = match b[i + 1] {
            b'x' => (hex(i + 2, 2), 4),
            b'u' if b.get(i + 2) == Some(&b'{') => match s[i + 3..].find('}') {
                Some(n) if (1..=6).contains(&n) => (hex(i + 3, n), n + 4),
                _ => (None, 2),
            },
            b'u' => (hex(i + 2, 4), 6),
            b'U' => (hex(i + 2, 8), 10),
            _ => (None, 2),
        };
        match code.and_then(char::from_u32).filter(|c| !c.is_control()) {
            Some(c) => {
                out.push_str(&s[copied..i]);
                out.push(c);
                i += len;
                copied = i;
                changed = true;
            }
            // Skip the escaped character too, so `\\\\x41` stays a backslash and text.
            None => i += 2,
        }
    }
    if !changed {
        return None;
    }
    out.push_str(&s[copied..]);
    Some(out)
}

/// Decoded text for each string token (`None` where nothing changed); see
/// [`decode_escapes`]. Shell strings and Python raw strings are left alone. `src` is the
/// text `toks` were lexed from.
pub fn decoded_strings(src: &str, toks: &[Token<'_>], lang: Lang) -> Vec<Option<String>> {
    toks.iter()
        .map(|t| {
            let raw = lang == Lang::Python && py_raw(src, t);
            (lang != Lang::Shell && t.kind == TokKind::Str && !raw)
                .then(|| decode_escapes(t.text))
                .flatten()
        })
        .collect()
}

/// Whether a Python string token carries an `r` prefix. The lexer drops the prefix, so it
/// is read back from the source in front of the opening quotes.
fn py_raw(src: &str, t: &Token<'_>) -> bool {
    let b = src.as_bytes();
    let Some(mut k) = (t.text.as_ptr() as usize).checked_sub(src.as_ptr() as usize) else {
        return false;
    };
    if k > b.len() {
        return false;
    }
    let mut quotes = 0;
    while quotes < 3 && k > 0 && matches!(b[k - 1], b'\'' | b'"') {
        k -= 1;
        quotes += 1;
    }
    let end = k;
    while k > 0 && end - k < 2 && b[k - 1].is_ascii_alphabetic() {
        k -= 1;
    }
    let glued = k > 0 && (b[k - 1].is_ascii_alphanumeric() || b[k - 1] == b'_');
    quotes > 0 && !glued && b[k..end].iter().any(|c| c.eq_ignore_ascii_case(&b'r'))
}

/// `toks` with each decoded string from [`decoded_strings`] in place of its source text.
pub fn with_decoded<'a>(toks: &[Token<'a>], decoded: &'a [Option<String>]) -> Vec<Token<'a>> {
    toks.iter()
        .zip(decoded)
        .map(|(t, d)| match d {
            Some(text) => Token { text, ..*t },
            None => *t,
        })
        .collect()
}

/// One step of a reversal pattern: a punctuation or name token with this text, the
/// reversed literal itself, or an empty string literal.
#[derive(Clone, Copy)]
enum Pat {
    T(&'static str),
    Lit,
    Empty,
}

/// Ways to reverse a string literal at run time, as a pattern prefix and suffix. Malware
/// stores a host, path or module name backwards and reverses it before use, so literal
/// matching misses it.
type Reversal = (&'static [Pat], &'static [Pat]);
const PY_REVERSALS: &[Reversal] = &[
    // 'lit'[::-1]
    (
        &[
            Pat::Lit,
            Pat::T("["),
            Pat::T(":"),
            Pat::T(":"),
            Pat::T("-"),
            Pat::T("1"),
            Pat::T("]"),
        ],
        &[],
    ),
    // ''.join(reversed('lit'))
    (
        &[
            Pat::Empty,
            Pat::T("."),
            Pat::T("join"),
            Pat::T("("),
            Pat::T("reversed"),
            Pat::T("("),
        ],
        &[Pat::Lit, Pat::T(")"), Pat::T(")")],
    ),
];
/// `.reverse().join('')`
const JS_REVERSE_JOIN: &[Pat] = &[
    Pat::T("."),
    Pat::T("reverse"),
    Pat::T("("),
    Pat::T(")"),
    Pat::T("."),
    Pat::T("join"),
    Pat::T("("),
    Pat::Empty,
    Pat::T(")"),
];
const JS_REVERSALS: &[Reversal] = &[
    // 'lit'.split('').reverse().join('')
    (
        &[
            Pat::Lit,
            Pat::T("."),
            Pat::T("split"),
            Pat::T("("),
            Pat::Empty,
            Pat::T(")"),
        ],
        JS_REVERSE_JOIN,
    ),
    // [...'lit'].reverse().join('')
    (
        &[Pat::T("["), Pat::T("..."), Pat::Lit, Pat::T("]")],
        JS_REVERSE_JOIN,
    ),
];

/// String literals reversed at run time (see [`PY_REVERSALS`] and [`JS_REVERSALS`]):
/// `(first, end, literal index, reversed text)`, where `first..end` is the token range the
/// expression covers. Run on decoded tokens, so an escaped literal is reversed as decoded.
pub fn reversed_literals(toks: &[Token<'_>], lang: Lang) -> Vec<(usize, usize, usize, String)> {
    let pats = match lang {
        Lang::Python => PY_REVERSALS,
        Lang::Js => JS_REVERSALS,
        Lang::Shell => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut i = 0;
    'next: while i < toks.len() {
        for (prefix, suffix) in pats {
            let n = prefix.len() + suffix.len();
            let mut lit = None;
            let matched = n <= toks.len() - i
                && prefix
                    .iter()
                    .chain(*suffix)
                    .zip(&toks[i..])
                    .enumerate()
                    .all(|(k, (p, t))| match p {
                        Pat::Lit if t.kind == TokKind::Str => {
                            lit = Some(i + k);
                            true
                        }
                        Pat::Empty => t.kind == TokKind::Str && t.text.is_empty(),
                        Pat::T(x) => t.kind != TokKind::Str && t.text == *x,
                        Pat::Lit => false,
                    });
            if let (true, Some(l)) = (matched, lit) {
                // Python joins adjacent literals before the subscript applies, so
                // `'a' 'b'[::-1]` reverses 'ab'.
                let mut run = l;
                if lang == Lang::Python && l == i {
                    let done = out
                        .last()
                        .map_or(0, |r: &(usize, usize, usize, String)| r.1);
                    while run > done && toks[run - 1].kind == TokKind::Str {
                        run -= 1;
                    }
                }
                let text: String = toks[run..=l].iter().map(|t| t.text).collect();
                out.push((i.min(run), i + n, run, text.chars().rev().collect()));
                i += n;
                continue 'next;
            }
        }
        i += 1;
    }
    out
}

/// `toks` with each reversal from [`reversed_literals`] replaced by one string token that
/// holds the reversed text, on the literal's line.
pub fn with_reversed<'a>(
    toks: &[Token<'a>],
    revs: &'a [(usize, usize, usize, String)],
) -> Vec<Token<'a>> {
    if revs.is_empty() {
        return toks.to_vec();
    }
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    for (first, end, lit, text) in revs {
        out.extend_from_slice(&toks[i..*first]);
        out.push(Token { text, ..toks[*lit] });
        i = *end;
    }
    out.extend_from_slice(&toks[i..]);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes_decode() {
        let d = |s: &str| decode_escapes(s);
        assert_eq!(
            d(r"\x63hild_\u0070rocess").as_deref(),
            Some("child_process")
        );
        assert_eq!(d(r"\u{68}ttp://x").as_deref(), Some("http://x"));
        assert_eq!(d(r"\U00000068i").as_deref(), Some("hi"));
        assert_eq!(d(r"a\nb\x0a"), None, "control characters stay escaped");
        assert_eq!(d(r"\\x41"), None, "an escaped backslash is not an escape");
        assert_eq!(d(r"\\\x41").as_deref(), Some(r"\\A"));
        assert_eq!(d(r"\xZZ \u12 \u{} \u{1234567}"), None);
        assert_eq!(d(r"\ud83d"), None, "lone surrogates are not characters");
        assert_eq!(d("plain"), None);

        // Raw prefixes are read back from the source; bytes literals still decode.
        let src = r#"a = r'\x41' + rb"\x41" + b'\x41' + R'''\x41''' + bar'\x41' + '\x41'"#;
        let toks = lex(src, Lang::Python);
        let dec: Vec<Option<String>> = decoded_strings(src, &toks, Lang::Python)
            .into_iter()
            .zip(&toks)
            .filter(|(_, t)| t.kind == TokKind::Str)
            .map(|(d, _)| d)
            .collect();
        let a = Some("A".to_string());
        assert_eq!(dec, vec![None, None, a.clone(), None, a.clone(), a]);
        assert_eq!(d(r"tail\").as_deref(), None);
        assert_eq!(d(r"\xe9t\xe9").as_deref(), Some("\u{e9}t\u{e9}"));
    }

    #[test]
    fn reversals() {
        let rev = |src: &str, lang: Lang| -> Vec<(TokKind, String)> {
            let toks = lex(src, lang);
            let revs = reversed_literals(&toks, lang);
            with_reversed(&toks, &revs)
                .iter()
                .map(|t| (t.kind, t.text.to_string()))
                .collect()
        };
        let s = |x: &str| (TokKind::Str, x.to_string());
        let p = |x: &str| (TokKind::Punct, x.to_string());
        let i = |x: &str| (TokKind::Ident, x.to_string());
        assert_eq!(
            rev("x = 'ss.c'[::-1]", Lang::Python),
            vec![i("x"), p("="), s("c.ss")]
        );
        assert_eq!(
            rev("''.join(reversed(\"so\"))", Lang::Python),
            vec![s("os")]
        );
        assert_eq!(
            rev(
                "require('ssecorp_dlihc'.split('').reverse().join(''))",
                Lang::Js
            ),
            vec![i("require"), p("("), s("child_process"), p(")")]
        );
        assert_eq!(
            rev("f([...\"sj.x\"].reverse().join(''))", Lang::Js),
            vec![i("f"), p("("), s("x.js"), p(")")]
        );
        // Slices other than a full reversal, and joins with a separator, stay as written.
        assert_eq!(rev("'abc'[::-2]", Lang::Python).len(), 7);
        assert_eq!(rev("'abc'[::1]", Lang::Python).len(), 6);
        assert_eq!(
            rev("'abc'.split('').reverse().join(',')", Lang::Js).len(),
            15
        );
        assert!(reversed_literals(&lex("'x'[::-1]", Lang::Shell), Lang::Shell).is_empty());
        // Python reverses adjacent literals as one; JavaScript has no implicit joining.
        assert_eq!(
            rev("x = 'ab' 'cd'[::-1]", Lang::Python),
            vec![i("x"), p("="), s("dcba")]
        );
        assert_eq!(
            rev("f('ab' 'cd'[::-1], 'ef'[::-1])", Lang::Python),
            vec![i("f"), p("("), s("dcba"), p(","), s("fe"), p(")")]
        );
        // The reversed token keeps the literal's line.
        let toks = lex("a = 1\nb = (\n  'x'\n)[::-1]\n", Lang::Python);
        let revs = reversed_literals(&toks, Lang::Python);
        assert!(revs.is_empty(), "a parenthesized literal is not matched");
        let toks = lex("a = 1\nb = 'yx'[::-1]\n", Lang::Python);
        let revs = reversed_literals(&toks, Lang::Python);
        let out = with_reversed(&toks, &revs);
        let t = out.iter().find(|t| t.kind == TokKind::Str).unwrap();
        assert_eq!((t.text, t.line), ("xy", 2));
    }

    use super::*;

    fn kinds<'a>(toks: &[Token<'a>]) -> Vec<(TokKind, &'a str)> {
        toks.iter()
            .filter(|t| t.kind != TokKind::Newline)
            .map(|t| (t.kind, t.text))
            .collect()
    }

    #[test]
    fn python_comments_and_strings() {
        let toks = lex(
            "# import subprocess\nx = 'subprocess'  # os.system\nos.system(x)\n",
            Lang::Python,
        );
        let k = kinds(&toks);
        assert_eq!(
            k,
            vec![
                (TokKind::Ident, "x"),
                (TokKind::Punct, "="),
                (TokKind::Str, "subprocess"),
                (TokKind::Ident, "os"),
                (TokKind::Punct, "."),
                (TokKind::Ident, "system"),
                (TokKind::Punct, "("),
                (TokKind::Ident, "x"),
                (TokKind::Punct, ")"),
            ]
        );
        assert_eq!(toks.iter().find(|t| t.text == "system").unwrap().line, 3);
    }

    #[test]
    fn python_prefixed_and_triple_strings() {
        let src = "a = rb'\\x00'\nb = \"\"\"doc\nstring\"\"\"\nc = f\"{x}\"\nd = 1\n";
        let toks = lex(src, Lang::Python);
        let strs: Vec<_> = toks
            .iter()
            .filter(|t| t.kind == TokKind::Str)
            .map(|t| t.text)
            .collect();
        assert_eq!(strs, vec!["\\x00", "doc\nstring", "{x}"]);
        assert_eq!(toks.iter().find(|t| t.text == "d").unwrap().line, 5);
        assert!(!toks.iter().any(|t| t.text == "rb" || t.text == "f"));
    }

    #[test]
    fn python_newlines_only_outside_brackets() {
        let toks = lex("f(a,\n  b)\nimport os\n", Lang::Python);
        let n = toks.iter().filter(|t| t.kind == TokKind::Newline).count();
        assert_eq!(n, 2);
    }

    #[test]
    fn js_comments_regex_and_templates() {
        let src = "// require('child_process')\n/* eval(x) */ const r = /ab+c\\//g; const y = a / b / c;\nlet t = `pre ${require(\"os\").hostname()} post`;\n";
        let toks = lex(src, Lang::Js);
        let k = kinds(&toks);
        assert!(k.contains(&(TokKind::Regex, "ab+c\\/")));
        assert!(!k.iter().any(|(_, t)| *t == "child_process" || *t == "eval"));
        assert!(k.contains(&(TokKind::Str, "pre ")));
        assert!(k.contains(&(TokKind::Str, "os")));
        assert!(k.contains(&(TokKind::Ident, "hostname")));
        assert!(k.contains(&(TokKind::Str, " post")));
        let slashes = k.iter().filter(|(_, t)| *t == "/").count();
        assert_eq!(slashes, 2);
        assert_eq!(toks.iter().find(|t| t.text == "hostname").unwrap().line, 3);
    }

    #[test]
    fn js_nested_template_braces() {
        let toks = lex("x = `a${ {k: 1}.k }b`; z", Lang::Js);
        let k = kinds(&toks);
        assert!(k.contains(&(TokKind::Str, "b")));
        assert_eq!(k.last(), Some(&(TokKind::Ident, "z")));
    }

    #[test]
    fn shell_words_and_comments() {
        let toks = lex(
            "# curl x | sh\ncurl -fsSL 'http://x' | sh\nREM whoami\n",
            Lang::Shell,
        );
        let k = kinds(&toks);
        assert_eq!(
            k,
            vec![
                (TokKind::Ident, "curl"),
                (TokKind::Ident, "-fsSL"),
                (TokKind::Str, "http://x"),
                (TokKind::Punct, "|"),
                (TokKind::Ident, "sh"),
            ]
        );
    }

    #[test]
    fn strip_shell_comments_keeps_offsets() {
        let src = "echo a # curl x|sh\necho '#not' b\n:: whoami\n";
        let out = strip_shell_comments(src);
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("curl"));
        assert!(out.contains("'#not'"));
        assert!(!out.contains("whoami"));
    }

    #[test]
    fn unterminated_string_stops_at_newline() {
        let toks = lex("a = 'oops\nimport socket\n", Lang::Python);
        assert!(toks
            .iter()
            .any(|t| t.kind == TokKind::Ident && t.text == "socket"));
    }
}
