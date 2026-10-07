//! Human-readable phrases for feature names, shown next to the numbers in verdicts.
//!
//! Indicator families (DESIGN.md 4.2) are phrased once and qualified by surface: `inst_`
//! features add "at install time" because that is what makes them dangerous; `all_`
//! features describe the whole archive.

/// Indicator family to a verb phrase.
const FAMILIES: &[(&str, &str)] = &[
    ("proc_exec", "Runs shell commands"),
    ("dyn_code", "Evaluates dynamically built code"),
    ("network", "Makes network requests"),
    ("decode_obf", "Decodes obfuscated or encoded data"),
    ("env_access", "Reads environment variables"),
    ("secret_paths", "References credential files or stores"),
    (
        "persistence",
        "Sets up persistence (cron, shell profiles, autoruns)",
    ),
    ("recon", "Collects host and user information"),
    ("download_exec", "Downloads and executes a payload"),
    ("exfil_endpoint", "Contacts a known exfiltration endpoint"),
    ("ip_url", "Contains a URL with a raw IP address"),
    ("url", "Contains URLs"),
    ("file_write", "Writes files"),
    ("crypto_wallet", "References cryptocurrency wallets"),
];

/// Structural, obfuscation, manifest, and name features.
const OTHER: &[(&str, &str)] = &[
    ("n_files", "Number of files"),
    ("total_bytes", "Total unpacked size"),
    ("max_file_bytes", "Largest file size"),
    ("n_py", "Number of Python files"),
    ("n_js", "Number of JavaScript files"),
    ("n_shell", "Contains shell or batch scripts"),
    ("n_binary", "Contains native executables"),
    ("n_hidden", "Contains hidden dotfiles"),
    ("inst_n_files", "Number of files that run at install time"),
    ("n_links", "Contains symlinks or hardlinks"),
    (
        "n_unsafe_paths",
        "Contains absolute or path-traversal entries",
    ),
    ("n_minified_js", "Contains minified JavaScript"),
    ("has_setup_py", "Has a setup.py that runs on install"),
    ("has_pyproject", "Has a pyproject.toml"),
    ("has_package_json", "Has a package.json"),
    ("n_npm_install_scripts", "Declares npm install scripts"),
    ("inst_n_lines", "Size of install-time code (lines)"),
    ("inst_bytes", "Size of install-time code (bytes)"),
    ("all_n_lines", "Size of all code (lines)"),
    ("inst_max_line_len", "Very long lines in install-time code"),
    ("all_max_line_len", "Very long lines in code"),
    (
        "inst_max_str_entropy",
        "High-entropy strings in install-time code",
    ),
    ("all_max_str_entropy", "High-entropy strings in code"),
    (
        "inst_mean_str_entropy",
        "Random-looking strings in install-time code",
    ),
    (
        "inst_longest_b64_run",
        "Long base64 blob in install-time code",
    ),
    ("all_longest_b64_run", "Long base64 blob in code"),
    (
        "inst_hex_escape_count",
        "Hex-escaped strings in install-time code",
    ),
    ("all_hex_escape_count", "Hex-escaped strings in code"),
    (
        "inst_obf_ident_ratio",
        "Obfuscated identifiers in install-time code",
    ),
    (
        "inst_nonascii_ratio",
        "Non-ASCII characters in install-time code",
    ),
    (
        "inst_long_line_ratio",
        "Many extremely long lines in install-time code",
    ),
    (
        "inst_hidden_ws_lines",
        "Install-time code hidden after a long run of blanks",
    ),
    (
        "all_hidden_ws_lines",
        "Code hidden after a long run of blanks",
    ),
    (
        "inst_exec_decoded",
        "Install-time code runs decoded data on the same line",
    ),
    ("all_exec_decoded", "Runs decoded data on the same line"),
    (
        "inst_max_file_kinds",
        "Most kinds of risky behavior in one install-time file",
    ),
    (
        "all_max_file_kinds",
        "Most kinds of risky behavior in one file",
    ),
    (
        "all_top_file_share",
        "Share of risky behavior in the busiest file",
    ),
    ("meta_desc_len", "Length of the package description"),
    ("meta_has_homepage", "Declares a homepage"),
    ("meta_has_repo", "Declares a source repository"),
    ("meta_has_author_email", "Declares an author email"),
    ("meta_has_license", "Declares a license"),
    ("meta_n_deps", "Number of dependencies"),
    ("meta_readme_bytes", "README size"),
    ("meta_version_major", "Major version number"),
    (
        "meta_version_is_zero",
        "Placeholder version (0.0.0 or 0.0.1)",
    ),
    (
        "meta_version_huge",
        "Suspiciously high version (dependency confusion)",
    ),
    ("meta_n_keywords", "Number of keywords"),
    ("name_len", "Name length"),
    ("name_n_digits", "Digits in the name"),
    ("name_n_hyphens", "Hyphens in the name"),
    ("name_n_underscores", "Underscores in the name"),
    ("name_n_dots", "Dots in the name"),
    ("name_has_scope", "Name has an npm scope"),
    ("name_is_popular", "Is a popular package"),
    ("name_dist1", "Name is 1 edit from a popular package"),
    ("name_dist2", "Name is 2 edits from a popular package"),
    ("name_dist3", "Name is 3 edits from a popular package"),
    (
        "name_contains_popular_token",
        "Name wraps a popular package name",
    ),
    ("name_digit_suffix", "Name ends in a digit"),
    (
        "name_char_ngram_score",
        "Name has unusual character patterns",
    ),
];

/// Phrase for a feature, or `None` when the name is unknown.
pub fn label(feature: &str) -> Option<String> {
    if let Some((_, l)) = OTHER.iter().find(|(f, _)| *f == feature) {
        return Some((*l).to_string());
    }
    let (rest, suffix) = if let Some(r) = feature.strip_prefix("inst_") {
        (r, " at install time")
    } else {
        (feature.strip_prefix("all_")?, "")
    };
    FAMILIES
        .iter()
        .find(|(f, _)| *f == rest)
        .map(|(_, l)| format!("{l}{suffix}"))
}

/// Phrase for a feature, falling back to the raw feature name.
pub fn label_or_name(feature: &str) -> String {
    label(feature).unwrap_or_else(|| feature.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrases() {
        assert_eq!(
            label("inst_proc_exec").unwrap(),
            "Runs shell commands at install time"
        );
        assert_eq!(label("all_network").unwrap(), "Makes network requests");
        assert_eq!(label("n_binary").unwrap(), "Contains native executables");
        assert_eq!(label("bogus"), None);
        assert_eq!(label_or_name("bogus"), "bogus");
    }

    #[test]
    fn every_schema_feature_has_a_label() {
        // Indicator families x surfaces plus the structural list should cover the schema.
        for (f, _) in FAMILIES {
            assert!(label(&format!("inst_{f}")).is_some());
            assert!(label(&format!("all_{f}")).is_some());
        }
        for name in customs_scan::feature_names() {
            assert!(label(name).is_some(), "missing label for {name}");
        }
    }
}
