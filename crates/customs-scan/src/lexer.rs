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

#[cfg(test)]
mod tests {
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
