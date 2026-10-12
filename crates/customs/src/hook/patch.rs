//! Codex's `apply_patch` format: which files a patch touches, and what an Update section
//! leaves in a file. The hook reads patches to find MCP server configurations they add
//! or change; it never writes the result anywhere.

use serde_json::{json, Value};

/// The files an `apply_patch` patch touches, each with its header and the lines it adds
/// or removes (`content`). Paths come from `*** Add File:`, `*** Update File:`,
/// `*** Delete File:` and `*** Move to:` headers.
pub(super) fn patch_files(patch: &str) -> Vec<(String, Value)> {
    let mut files: Vec<(String, String)> = Vec::new();
    for line in patch.lines() {
        let header = [
            "*** Add File:",
            "*** Update File:",
            "*** Delete File:",
            "*** Move to:",
        ]
        .iter()
        .find_map(|h| line.strip_prefix(h));
        if let Some(path) = header {
            files.push((path.trim().to_string(), format!("{line}\n")));
        } else if let (true, Some((_, text))) = (line.starts_with(['+', '-']), files.last_mut()) {
            text.push_str(line);
            text.push('\n');
        }
    }
    files
        .into_iter()
        .map(|(path, added)| (path, json!({ "content": added })))
        .collect()
}

/// What an `apply_patch` patch does to one file.
#[derive(Debug, PartialEq)]
pub(super) enum PatchOp {
    Add,
    Update,
    Delete,
}

/// One file's part of an `apply_patch` patch: its path, where it moves to, and its lines.
#[derive(Debug)]
pub(super) struct PatchSection {
    pub(super) op: PatchOp,
    pub(super) path: String,
    pub(super) move_to: Option<String>,
    pub(super) lines: Vec<String>,
}

pub(super) fn patch_sections(patch: &str) -> Vec<PatchSection> {
    let mut sections: Vec<PatchSection> = Vec::new();
    for line in patch.lines() {
        let line = line.trim_end_matches('\r');
        let header = [
            ("*** Add File:", PatchOp::Add),
            ("*** Update File:", PatchOp::Update),
            ("*** Delete File:", PatchOp::Delete),
        ]
        .into_iter()
        .find_map(|(h, op)| line.strip_prefix(h).map(|p| (op, p.trim().to_string())));
        if let Some((op, path)) = header {
            sections.push(PatchSection {
                op,
                path,
                move_to: None,
                lines: Vec::new(),
            });
        } else if let Some(to) = line.strip_prefix("*** Move to:") {
            if let Some(s) = sections.last_mut() {
                s.move_to = Some(to.trim().to_string());
            }
        } else if line.starts_with("*** ") {
            // `*** Begin Patch`, `*** End Patch`, `*** End of File`.
        } else if let Some(s) = sections.last_mut() {
            s.lines.push(line.to_string());
        }
    }
    sections
}

/// Where `old` occurs in `file` from line `from` on, compared exactly, then without
/// trailing and then without surrounding white space, the way `apply_patch` matches.
fn find_lines(file: &[String], old: &[String], from: usize) -> Option<usize> {
    if old.len() > file.len() {
        return None;
    }
    let same: [fn(&str, &str) -> bool; 3] = [
        |a, b| a == b,
        |a, b| a.trim_end() == b.trim_end(),
        |a, b| a.trim() == b.trim(),
    ];
    same.iter().find_map(|eq| {
        (from..=file.len() - old.len()).find(|&i| {
            file[i..i + old.len()]
                .iter()
                .zip(old)
                .all(|(a, b)| eq(a, b))
        })
    })
}

/// `original` with an Update section's hunks applied. `None` when a hunk does not match.
pub(super) fn apply_hunks(original: &str, lines: &[String]) -> Option<String> {
    // Each hunk: the `@@` line it follows, the lines it expects, the lines it leaves.
    let mut hunks: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for l in lines {
        if let Some(anchor) = l.strip_prefix("@@") {
            hunks.push((anchor.trim().to_string(), Vec::new(), Vec::new()));
            continue;
        }
        if hunks.is_empty() {
            hunks.push((String::new(), Vec::new(), Vec::new()));
        }
        let (_, old, new) = hunks.last_mut()?;
        let mut chars = l.chars();
        match chars.next() {
            Some('+') => new.push(chars.as_str().to_string()),
            Some('-') => old.push(chars.as_str().to_string()),
            Some(' ') => {
                old.push(chars.as_str().to_string());
                new.push(chars.as_str().to_string());
            }
            None => {
                old.push(String::new());
                new.push(String::new());
            }
            Some(_) => return None,
        }
    }
    let mut file: Vec<String> = original.lines().map(str::to_string).collect();
    let mut cursor = 0;
    for (anchor, old, new) in hunks {
        if !anchor.is_empty() {
            cursor = 1 + (cursor..file.len()).find(|&i| file[i].trim() == anchor)?;
        }
        if old.is_empty() {
            // Lines added with no context go at the end.
            file.extend(new);
            cursor = file.len();
            continue;
        }
        let at = find_lines(&file, &old, cursor)?;
        cursor = at + new.len();
        file.splice(at..at + old.len(), new);
    }
    let mut text = file.join("\n");
    text.push('\n');
    Some(text)
}
