//! A second look at install-time code, read the way the interpreter reads it.
//!
//! The feature lexers end lines only at `\n`, keep a byte-order mark glued to the first
//! token, and read a Python f-string as one string. CPython and Node also end lines at a
//! bare `\r` (Node also at U+2028 and U+2029), drop the mark, and run the code in f-string
//! fields, so a payload written that way runs unseen. Changing those lexers would change
//! the model inputs of ordinary files that merely contain a stray `\r`, a mark or an
//! f-string. Instead, for install-surface files where the two readings can differ, the
//! scanner analyzes the interpreter's reading once more and reports the indicators only
//! that reading has (`ScanReport::hidden_code`). Features and tokens never see it.
//!
//! The same module reads PEP 263 coding cookies: a declared codec that is not
//! ASCII-transparent (UTF-7, `unicode_escape`, UTF-16, EBCDIC, ...) makes Python run text
//! that is not the bytes the scanner lexed.

use crate::indicators::{self, FileAnalysis, INDICATORS};
use crate::lexer::{lex, Lang, LexMode, TokKind};
use regex::Regex;
use std::sync::LazyLock;

/// Indicators whose appearance only in the interpreter's reading counts as hidden code.
/// `recon`, `env_access`, `url`, `file_write` and `decode_obf` are left out: benign
/// f-strings (`f"{platform.system()}"`, `f"{os.environ['HOME']}"`) hit them.
pub(crate) const HIDDEN: [usize; 9] = [
    indicators::PROC_EXEC,
    indicators::DYN_CODE,
    indicators::NETWORK,
    indicators::SECRET_PATHS,
    indicators::PERSISTENCE,
    indicators::DOWNLOAD_EXEC,
    indicators::EXFIL_ENDPOINT,
    indicators::IP_URL,
    indicators::CRYPTO_WALLET,
];

/// Why the interpreter's reading of a file differs from the feature lexers'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    BareCr,
    LineSeparator,
    BackslashCrlf,
    Bom,
    FstringField,
}

impl Why {
    pub(crate) fn phrase(self) -> &'static str {
        match self {
            Why::BareCr => "after a bare carriage return",
            Why::LineSeparator => "after a Unicode line separator",
            Why::BackslashCrlf => "after a backslash-CRLF continuation",
            Why::Bom => "after a byte-order mark",
            Why::FstringField => "inside an f-string field",
        }
    }
}

/// The interpreter's reading of a file.
pub(crate) struct View {
    /// The text the interpreter tokenizes, when it differs from the raw text.
    pub text: Option<String>,
    pub mode: LexMode,
    pub why: Vec<Why>,
}

impl View {
    /// `(code after X; code inside Y)`, for a `hidden_code` entry about the file itself.
    pub(crate) fn label(&self) -> String {
        let parts: Vec<String> = self
            .why
            .iter()
            .map(|w| format!("code {}", w.phrase()))
            .collect();
        format!("({})", parts.join("; "))
    }

    /// `after X and after Y`: why an import was missed (text changes only).
    pub(crate) fn import_cause(&self) -> String {
        let parts: Vec<&str> = self
            .why
            .iter()
            .filter(|w| **w != Why::FstringField)
            .map(|w| w.phrase())
            .collect();
        parts.join(" and ")
    }
}

/// An f-string or t-string prefix glued to its opening quote.
static FSTRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:^|[^A-Za-z0-9_])(?:f|t|fr|rf|tr|rt)['"]"#).unwrap());

/// How the interpreter's reading of `text` can differ from the feature lexers', or `None`
/// when it cannot.
pub(crate) fn view(text: &str, lang: Lang) -> Option<View> {
    let mut why = Vec::new();
    if text.starts_with('\u{feff}') {
        why.push(Why::Bom);
    }
    let b = text.as_bytes();
    if b.iter()
        .enumerate()
        .any(|(i, &c)| c == b'\r' && b.get(i + 1) != Some(&b'\n'))
    {
        why.push(Why::BareCr);
    }
    if text.contains("\\\r\n") {
        why.push(Why::BackslashCrlf);
    }
    // Line separators inside JavaScript string, template and regex literals end nothing.
    let mut keep: Vec<(usize, usize)> = Vec::new();
    if lang == Lang::Js && text.contains(['\u{2028}', '\u{2029}']) {
        let base = text.as_ptr() as usize;
        keep = lex(text, Lang::Js)
            .iter()
            .filter(|t| matches!(t.kind, TokKind::Str | TokKind::Regex))
            .map(|t| {
                let start = t.text.as_ptr() as usize - base;
                (start, start + t.text.len())
            })
            .collect();
        let outside = text
            .match_indices(['\u{2028}', '\u{2029}'])
            .any(|(i, _)| !inside(&keep, i));
        if outside {
            why.push(Why::LineSeparator);
        }
    }
    let fstrings = lang == Lang::Python && text.contains('{') && FSTRING.is_match(text);
    if fstrings {
        why.push(Why::FstringField);
    }
    if why.is_empty() {
        return None;
    }
    let rewrite = why.iter().any(|w| *w != Why::FstringField);
    let text = rewrite.then(|| interpreter_text(text, lang, &keep));
    Some(View {
        text,
        mode: LexMode {
            fstring_fields: fstrings,
        },
        why,
    })
}

/// Whether byte `i` lies in one of the `keep` spans, which are in order and do not overlap.
fn inside(keep: &[(usize, usize)], i: usize) -> bool {
    let after = keep.partition_point(|&(s, _)| s <= i);
    after > 0 && i < keep[after - 1].1
}

/// `text` with the byte-order mark dropped and every line end written as `\n`: `\r\n`,
/// a bare `\r` and, in JavaScript, U+2028 and U+2029 outside the `keep` literal spans.
fn interpreter_text(text: &str, lang: Lang, keep: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\u{feff}' if i == 0 => {}
            '\r' if chars.peek().is_some_and(|&(_, n)| n == '\n') => {}
            '\r' => out.push('\n'),
            '\u{2028}' | '\u{2029}' if lang == Lang::Js && !inside(keep, i) => out.push('\n'),
            _ => out.push(c),
        }
    }
    out
}

/// The [`HIDDEN`] indicators `seen` has more of than `main`, as `(first line, names)`.
/// The line is the first hit of those indicators that `main` does not also have.
pub(crate) fn more(main: &FileAnalysis, seen: &FileAnalysis) -> Option<(u32, String)> {
    let found: Vec<usize> = HIDDEN
        .iter()
        .copied()
        .filter(|&k| seen.counts[k] > main.counts[k])
        .collect();
    first_new(main, seen, found)
}

/// Like [`more`] for a reading that also runs f-string fields. `plain` is the reading
/// without them (the rewritten text, or `main` itself when only fields differ). Line-end
/// and mark tricks count wherever they add hits; fields count only for an indicator the
/// file shows nowhere else, since ordinary fields name modules the file already uses
/// (`f"{urllib3.__version__}"`).
pub(crate) fn more_with_fields(
    main: &FileAnalysis,
    plain: &FileAnalysis,
    seen: &FileAnalysis,
) -> Option<(u32, String)> {
    let found: Vec<usize> = HIDDEN
        .iter()
        .copied()
        .filter(|&k| {
            plain.counts[k] > main.counts[k] || (plain.counts[k] == 0 && seen.counts[k] > 0)
        })
        .collect();
    first_new(main, seen, found)
}

fn first_new(
    main: &FileAnalysis,
    seen: &FileAnalysis,
    mut found: Vec<usize>,
) -> Option<(u32, String)> {
    found.sort_unstable();
    let line = found
        .iter()
        .filter_map(|&k| {
            let mut have: Vec<u32> = main.hits.iter().filter(|h| h.0 == k).map(|h| h.1).collect();
            let mut lines: Vec<u32> = seen.hits.iter().filter(|h| h.0 == k).map(|h| h.1).collect();
            lines.sort_unstable();
            lines
                .into_iter()
                .find(|l| match have.iter().position(|h| h == l) {
                    Some(p) => {
                        have.swap_remove(p);
                        false
                    }
                    None => true,
                })
        })
        .min();
    let first = found.first()?;
    let line = line
        .or_else(|| seen.hits.iter().find(|h| h.0 == *first).map(|h| h.1))
        .unwrap_or(1);
    Some((line, names(&found)))
}

/// Every [`HIDDEN`] indicator in `a`, as `(first line, names)`.
pub(crate) fn any(a: &FileAnalysis) -> Option<(u32, String)> {
    more(&FileAnalysis::default(), a)
}

fn names(found: &[usize]) -> String {
    found
        .iter()
        .map(|&k| INDICATORS[k])
        .collect::<Vec<_>>()
        .join(", ")
}

/// The PEP 263 cookie regex (`^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)`).
static COOKIE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[ \t\x0c]*#.*?coding[:=][ \t]*([-\w.]+)").unwrap());

/// Codecs a coding cookie on line 1 or 2 names. CPython reads either line; a bare `\r` ends
/// a line too, so both ways of splitting are tried.
pub(crate) fn coding_cookies(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let by_lf = text.split('\n').take(2);
    let crlf = text.replace("\r\n", "\n");
    let by_any = crlf.split(['\r', '\n']).take(2);
    let mut out: Vec<String> = Vec::new();
    for line in by_lf.chain(by_any) {
        if let Some(c) = COOKIE.captures(line) {
            let name = c[1].to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Whether Python, decoding `data` with `codec`, reads the same ASCII text the scanner
/// lexed: UTF-8 and its aliases, single-byte ASCII supersets, and EUC-style multibyte
/// codecs whose bytes never overlap ASCII. Shift JIS, GBK and Big5 also qualify when no
/// non-ASCII byte is followed by ASCII punctuation, since their second bytes include `\`,
/// which would stop escaping a quote. Anything else (UTF-7, `unicode_escape`, UTF-16, HZ,
/// ISO-2022, EBCDIC, ...) can turn bytes into different code.
pub(crate) fn ascii_transparent(codec: &str, data: &[u8]) -> bool {
    static SINGLE_BYTE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            r"^(?:utf-?8(?:-.*)?|u8|utf|cp65001|ascii|us-ascii|646",
            r"|iso-?8859-\d+|latin-?\d*|l\d+|iso-latin-1|cp819",
            r"|(?:cp|windows-)125[0-8]",
            r"|cp(?:437|720|737|775|85[0-8]|86[0-3]|865|866|869|874)",
            r"|koi8-[rtu]|macintosh|mac-?(?:roman|latin2|cyrillic|greek|iceland|turkish|croatian|romanian)",
            r"|euc-?(?:jp|kr|cn|jis-?2004|jisx0213)|ujis|gb2312|cp949|uhc)$",
        ))
        .unwrap()
    });
    static SECOND_BYTE_ASCII: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            r"^(?:gbk|gb18030|cp936|ms936|big5|big5-?hkscs|cp950",
            r"|shift-?jis(?:-?2004|x0213)?|s-?jis|cp932|ms932|ms-?kanji)$",
        ))
        .unwrap()
    });
    let c = codec.to_ascii_lowercase().replace(['_', ' '], "-");
    if SINGLE_BYTE.is_match(&c) {
        return true;
    }
    SECOND_BYTE_ASCII.is_match(&c)
        && !data
            .windows(2)
            .any(|w| w[0] >= 0x80 && (0x40..=0x7e).contains(&w[1]) && !w[1].is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Many line separators inside many string literals: finding the literal around each
    /// separator is a search, not a walk over every literal.
    #[test]
    fn many_line_separators_in_strings_stay_linear() {
        let text = format!("\u{feff}{}", "'\u{2028}xx',".repeat(300_000));
        let started = std::time::Instant::now();
        let v = view(&text, Lang::Js).expect("the BOM needs a rewrite");
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(5), "{took:?}");
        assert_eq!(v.why, vec![Why::Bom]);
        // Inside literals, separators are kept; only the BOM goes.
        assert_eq!(v.text.as_deref(), Some(&text[3..]));
    }

    #[test]
    fn plain_files_need_no_second_look() {
        assert!(view("import os\r\nos.getcwd()\r\n", Lang::Python).is_none());
        assert!(view("const a = '\u{2028}';\n", Lang::Js).is_none());
        assert!(view("x = '{}'.format(1)\n", Lang::Python).is_none());
    }

    #[test]
    fn interpreter_text_ends_lines_like_the_interpreter() {
        let v = view(
            "\u{feff}# a\rb = 1\r\nc\u{2028}d = 'e\u{2028}f'\n",
            Lang::Js,
        )
        .unwrap();
        assert_eq!(v.why, [Why::Bom, Why::BareCr, Why::LineSeparator]);
        assert_eq!(v.text.unwrap(), "# a\nb = 1\nc\nd = 'e\u{2028}f'\n");
        let v = view("x = f'{y}'\n", Lang::Python).unwrap();
        assert_eq!(v.why, [Why::FstringField]);
        assert!(v.text.is_none() && v.mode.fstring_fields);
    }

    #[test]
    fn cookies_on_the_first_two_lines() {
        assert_eq!(
            coding_cookies("#!/bin/python\n# -*- coding: utf-7 -*-\n"),
            ["utf-7"]
        );
        assert_eq!(coding_cookies("# x\r# vim: fileencoding=hz\n"), ["hz"]);
        assert!(coding_cookies("x = 1\ny = 2\n# coding: utf-7\n").is_empty());
        assert!(ascii_transparent("UTF-8", b""));
        assert!(ascii_transparent("Latin-1", b"\xe9"));
        assert!(!ascii_transparent("utf_7", b""));
        assert!(!ascii_transparent("raw_unicode_escape", b""));
        assert!(ascii_transparent("cp932", b"x = '\x82\xa0'"));
        assert!(!ascii_transparent("cp932", b"x = '\x81\\'"));
    }
}
