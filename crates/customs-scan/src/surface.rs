//! Install-surface resolution (DESIGN.md section 4.1): which code runs at install or import
//! time without the user calling anything.

use crate::lexer::Lang;

/// npm lifecycle scripts that run on `npm install` of the package or of a git dependency.
pub const NPM_INSTALL_HOOKS: [&str; 6] = [
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
];

/// What an npm script command runs: files it points at, inline code (`node -e`), and other
/// package.json scripts it invokes by name (`npm run build`).
#[derive(Debug, Default, PartialEq)]
pub struct CommandRefs {
    pub files: Vec<(String, Lang)>,
    pub inline: Vec<(String, Lang)>,
    pub scripts: Vec<String>,
}

/// Shell commands in gyp command expansions (`<!(cmd)` and `<!@(cmd)`) with the line each
/// starts on. node-gyp runs them while it configures the build, so a `binding.gyp` that
/// npm builds at install runs them at install. Parentheses inside a command nest, as gyp
/// counts them.
pub fn gyp_commands(text: &str) -> Vec<(String, u32)> {
    const MAX_COMMANDS: usize = 32;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() < MAX_COMMANDS {
        let Some(at) = text[pos..].find("<!").map(|i| pos + i) else {
            break;
        };
        // Index of the opening parenthesis.
        let open = match &text[at + 2..] {
            t if t.starts_with('(') => at + 2,
            t if t.starts_with("@(") => at + 3,
            _ => {
                pos = at + 2;
                continue;
            }
        };
        let mut depth = 0usize;
        let mut close = None;
        for (i, c) in text[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            break;
        };
        // The command sits in a JSON or Python string literal: undo its escapes.
        let mut cmd = String::new();
        let mut chars = text[open + 1..close].trim().chars();
        while let Some(c) = chars.next() {
            match (c, chars.clone().next()) {
                ('\\', Some(n @ ('"' | '\'' | '\\'))) => {
                    cmd.push(n);
                    chars.next();
                }
                _ => cmd.push(c),
            }
        }
        if !cmd.is_empty() {
            let line = text[..at].matches('\n').count() as u32 + 1;
            out.push((cmd, line));
        }
        pos = close + 1;
    }
    out
}

/// Yarn commands that are not script names (`yarn <script>` runs a script otherwise).
const YARN_BUILTINS: [&str; 16] = [
    "add",
    "bin",
    "cache",
    "config",
    "dlx",
    "exec",
    "global",
    "info",
    "init",
    "install",
    "link",
    "node",
    "pack",
    "remove",
    "upgrade",
    "workspace",
];

fn looks_like_file(a: &str) -> bool {
    a.contains('/')
        || matches!(
            crate::archive::extension(a).to_ascii_lowercase().as_str(),
            "js" | "cjs" | "mjs" | "ts" | "mts" | "cts" | "tsx" | "jsx"
        )
}

/// Split a shell command into segments of words, honoring quotes. Operators (`&&`, `||`,
/// `;`, `|`, `&`) and subshell parentheses end a segment.
pub fn split_command(cmd: &str) -> Vec<Vec<String>> {
    let mut segs: Vec<Vec<String>> = vec![Vec::new()];
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars().peekable();
    let end_word = |segs: &mut Vec<Vec<String>>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            segs.last_mut().unwrap().push(std::mem::take(word));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    word.push(d);
                }
            }
            '"' => {
                in_word = true;
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                word.push(e);
                            }
                        }
                        _ => word.push(d),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(e) = chars.next() {
                    word.push(e);
                }
            }
            ';' | '&' | '|' | '(' | ')' | '\n' => {
                end_word(&mut segs, &mut word, &mut in_word);
                if !segs.last().unwrap().is_empty() {
                    segs.push(Vec::new());
                }
            }
            c if c.is_whitespace() => end_word(&mut segs, &mut word, &mut in_word),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    end_word(&mut segs, &mut word, &mut in_word);
    segs.retain(|s| !s.is_empty());
    segs
}

fn lang_for_path(p: &str, default: Lang) -> Lang {
    match crate::archive::extension(p).to_ascii_lowercase().as_str() {
        "py" => Lang::Python,
        "js" | "cjs" | "mjs" | "ts" => Lang::Js,
        "sh" | "bash" | "bat" | "cmd" | "ps1" => Lang::Shell,
        _ => default,
    }
}

/// Find the files and inline code an npm script command executes.
pub fn command_refs(cmd: &str) -> CommandRefs {
    let mut refs = CommandRefs::default();
    for seg in split_command(cmd) {
        let mut words = seg.iter().map(String::as_str).peekable();
        // Skip environment assignments and transparent wrappers.
        while let Some(&w) = words.peek() {
            let is_assign = w.contains('=') && !w.starts_with('-') && !w.starts_with('=');
            if is_assign || matches!(w, "cross-env" | "env" | "sudo" | "exec" | "npx" | "nohup") {
                words.next();
            } else {
                break;
            }
        }
        let Some(cmd) = words.next() else { continue };
        let base = cmd
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(cmd)
            .to_ascii_lowercase();
        let base = base.trim_end_matches(".exe");
        let args: Vec<&str> = words.collect();
        match base {
            "bun" if matches!(args.first(), Some(&("x" | "add" | "install" | "i" | "pm"))) => {}
            "bun" if args.first() == Some(&"run") => {
                // `bun run <file>` runs a file; `bun run <name>` runs a package.json script.
                if let Some(a) = args[1..].iter().find(|a| !a.starts_with('-')) {
                    if looks_like_file(a) {
                        refs.files.push((a.to_string(), Lang::Js));
                    } else {
                        refs.scripts.push(a.to_string());
                    }
                }
            }
            "npm" | "pnpm" => {
                if matches!(args.first(), Some(&("run" | "run-script"))) {
                    if let Some(a) = args[1..].iter().find(|a| !a.starts_with('-')) {
                        refs.scripts.push(a.to_string());
                    }
                }
            }
            "yarn" => {
                let rest: Vec<&str> = args
                    .iter()
                    .copied()
                    .filter(|a| !a.starts_with('-'))
                    .collect();
                match rest.as_slice() {
                    ["run", name, ..] => refs.scripts.push(name.to_string()),
                    [name, ..] if !YARN_BUILTINS.contains(name) && *name != "run" => {
                        refs.scripts.push(name.to_string())
                    }
                    _ => {}
                }
            }
            "run-s" | "run-p" | "npm-run-all" => {
                refs.scripts.extend(
                    args.iter()
                        .filter(|a| !a.starts_with('-') && !a.contains('*'))
                        .map(|a| a.to_string()),
                );
            }
            "node" | "nodejs" | "bun" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i];
                    if matches!(a, "-e" | "--eval" | "-p" | "--print") {
                        if let Some(code) = args.get(i + 1) {
                            refs.inline.push((code.to_string(), Lang::Js));
                        }
                        break;
                    } else if let Some(code) = a.strip_prefix("--eval=") {
                        refs.inline.push((code.to_string(), Lang::Js));
                        break;
                    } else if matches!(a, "-r" | "--require" | "--import" | "--loader") {
                        if let Some(f) = args.get(i + 1) {
                            refs.files.push((f.to_string(), Lang::Js));
                        }
                        i += 2;
                        continue;
                    } else if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    refs.files.push((a.to_string(), Lang::Js));
                    break;
                }
            }
            "sh" | "bash" | "zsh" | "dash" | "ksh" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i];
                    if a == "-c" {
                        if let Some(code) = args.get(i + 1) {
                            refs.inline.push((code.to_string(), Lang::Shell));
                        }
                        break;
                    } else if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    refs.files.push((a.to_string(), Lang::Shell));
                    break;
                }
            }
            b if b.starts_with("python") => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i];
                    if a == "-c" {
                        if let Some(code) = args.get(i + 1) {
                            refs.inline.push((code.to_string(), Lang::Python));
                        }
                        break;
                    } else if a == "-m" {
                        break;
                    } else if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    refs.files.push((a.to_string(), Lang::Python));
                    break;
                }
            }
            "powershell" | "pwsh" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i].to_ascii_lowercase();
                    if a == "-file" || a == "-f" {
                        if let Some(f) = args.get(i + 1) {
                            refs.files.push((f.to_string(), Lang::Shell));
                        }
                        break;
                    } else if a == "-command" || a == "-c" {
                        refs.inline.push((args[i + 1..].join(" "), Lang::Shell));
                        break;
                    }
                    i += 1;
                }
            }
            _ => {
                let direct = cmd.starts_with("./")
                    || cmd.starts_with("../")
                    || matches!(
                        crate::archive::extension(cmd).to_ascii_lowercase().as_str(),
                        "sh" | "js" | "py" | "bat" | "cmd" | "ps1"
                    );
                if direct {
                    refs.files
                        .push((cmd.to_string(), lang_for_path(cmd, Lang::Shell)));
                }
            }
        }
    }
    refs
}

/// Resolve `spec` relative to directory `dir` (both archive-relative). `..` may climb within
/// the archive but never above its root.
pub fn resolve_relative(dir: &str, spec: &str) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for comp in spec.split(['/', '\\']) {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Candidate files for a Node module path, in Node's resolution order.
pub fn node_candidates(path: &str) -> Vec<String> {
    let p = path.trim_end_matches('/');
    vec![
        p.to_string(),
        format!("{p}.js"),
        format!("{p}.cjs"),
        format!("{p}.mjs"),
        format!("{p}/index.js"),
    ]
}

/// Module paths named by `cmdclass` in `setup.cfg` (`install = pkg.cmds.Install`), as
/// candidate file paths.
pub fn setup_cfg_cmdclass_files(cfg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_cmdclass = false;
    for line in cfg.lines() {
        let t = line.trim();
        let continuation = line.starts_with([' ', '\t']) && !t.is_empty();
        if !continuation {
            in_cmdclass = false;
            if let Some((k, v)) = t.split_once('=') {
                if k.trim().eq_ignore_ascii_case("cmdclass") {
                    in_cmdclass = true;
                    out.extend(cmdclass_value(v));
                }
            }
        } else if in_cmdclass {
            if let Some((_, v)) = t.split_once('=') {
                out.extend(cmdclass_value(v));
            }
        }
    }
    out
}

fn cmdclass_value(v: &str) -> Vec<String> {
    let v = v.trim();
    let Some((module, _class)) = v.rsplit_once('.') else {
        return Vec::new();
    };
    if module.is_empty()
        || !module
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return Vec::new();
    }
    py_module_files(module, &["", "src/"])
}

/// Candidate files for a dotted Python module under the given roots.
pub fn py_module_files(module: &str, roots: &[&str]) -> Vec<String> {
    let rel = module.replace('.', "/");
    roots
        .iter()
        .flat_map(|r| [format!("{r}{rel}.py"), format!("{r}{rel}/__init__.py")])
        .collect()
}

/// In-tree PEP 517 build backend (`backend-path`), which runs during the build step.
pub fn in_tree_backend_files(pyproject: &str) -> Vec<String> {
    let Ok(v) = pyproject.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(bs) = v.get("build-system").and_then(|b| b.as_table()) else {
        return Vec::new();
    };
    let Some(backend) = bs.get("build-backend").and_then(|b| b.as_str()) else {
        return Vec::new();
    };
    let Some(paths) = bs.get("backend-path").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    let module = backend.split(':').next().unwrap_or(backend);
    let roots: Vec<String> = paths
        .iter()
        .filter_map(|p| p.as_str())
        .filter_map(|p| match resolve_relative("", p) {
            Some(r) => Some(format!("{r}/")),
            None if matches!(p, "." | "./" | "") => Some(String::new()),
            None => None,
        })
        .collect();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    py_module_files(module, &roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_respects_quotes_and_operators() {
        let segs = split_command("FOO=1 node ./x.js && sh -c 'curl a | sh'; echo \"a b\"");
        assert_eq!(
            segs,
            vec![
                vec!["FOO=1", "node", "./x.js"],
                vec!["sh", "-c", "curl a | sh"],
                vec!["echo", "a b"],
            ]
        );
    }

    #[test]
    fn node_and_shell_refs() {
        let r =
            command_refs("node scripts/install.js --flag && node -e \"require('child_process')\"");
        assert_eq!(r.files, vec![("scripts/install.js".to_string(), Lang::Js)]);
        assert_eq!(
            r.inline,
            vec![("require('child_process')".to_string(), Lang::Js)]
        );
        let r = command_refs("cross-env NODE_ENV=production node --max-old-space-size=4096 build");
        assert_eq!(r.files, vec![("build".to_string(), Lang::Js)]);
        let r = command_refs("sh ./setup.sh || ./post.sh");
        assert_eq!(
            r.files,
            vec![
                ("./setup.sh".to_string(), Lang::Shell),
                ("./post.sh".to_string(), Lang::Shell)
            ]
        );
        let r = command_refs("python3 -c 'import os'");
        assert_eq!(r.inline, vec![("import os".to_string(), Lang::Python)]);
        assert!(command_refs("node-gyp rebuild").files.is_empty());
        assert!(command_refs("husky install").files.is_empty());
    }

    #[test]
    fn bun_run_and_script_indirection() {
        let r = command_refs("bun run index.js");
        assert_eq!(r.files, vec![("index.js".to_string(), Lang::Js)]);
        assert!(r.scripts.is_empty());
        let r = command_refs("bun run build && npm run setup -- --x; yarn prep; yarn run gen");
        assert_eq!(r.scripts, vec!["build", "setup", "prep", "gen"]);
        assert!(r.files.is_empty());
        assert!(command_refs("yarn install --frozen-lockfile")
            .scripts
            .is_empty());
        assert!(command_refs("bun x tsc").files.is_empty());
        let r = command_refs("cross-env NODE_ENV=production run-s clean build:*");
        assert_eq!(r.scripts, vec!["clean"]);
        let r = command_refs("bun ./postinstall.mjs || node ./postinstall.mjs");
        assert_eq!(r.files.len(), 2);
    }

    #[test]
    fn gyp_command_expansions() {
        let gyp = r#"{
  "targets": [{
    "include_dirs": ["<!(node -e \"require('nan')\")", "<!@(node -p \"require('a').include\")"],
    "sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"],
    "defines": ["<(module_name)", "<!(unterminated"]
  }]
}"#;
        let cmds = gyp_commands(gyp);
        assert_eq!(
            cmds,
            vec![
                ("node -e \"require('nan')\"".to_string(), 3),
                ("node -p \"require('a').include\"".to_string(), 3),
                (
                    "node index.js > /dev/null 2>&1 && echo stub.c".to_string(),
                    4
                ),
            ]
        );
        let refs = command_refs(&cmds[2].0);
        assert_eq!(refs.files, vec![("index.js".to_string(), Lang::Js)]);
        assert!(gyp_commands("no expansions <(x)").is_empty());
    }

    #[test]
    fn relative_resolution() {
        assert_eq!(resolve_relative("lib", "./a"), Some("lib/a".into()));
        assert_eq!(
            resolve_relative("lib/x", "../b.js"),
            Some("lib/b.js".into())
        );
        assert_eq!(resolve_relative("", "../escape"), None);
    }

    #[test]
    fn cmdclass_and_backend() {
        let f =
            setup_cfg_cmdclass_files("[options]\ncmdclass =\n    install = mypkg.cmds.Install\n");
        assert!(f.contains(&"mypkg/cmds.py".to_string()));
        let b = in_tree_backend_files(
            "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\"_build\"]\n",
        );
        assert_eq!(b, vec!["_build/backend.py", "_build/backend/__init__.py"]);
    }
}
