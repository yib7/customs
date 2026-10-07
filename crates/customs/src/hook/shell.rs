//! Just enough of POSIX shell lexing to find the simple commands in a command line.
//!
//! The hook only needs words and command boundaries: quotes and escapes are removed,
//! `&&`, `||`, `;`, `|`, `&`, newlines and parentheses separate commands, redirections are
//! dropped with their targets, comments are skipped, and the bodies of `$(...)` and
//! backticks are lexed recursively and reported as extra commands, since an install hidden
//! in a substitution still runs.

/// Split a command line into simple commands (lists of words).
pub fn split_commands(input: &str) -> Vec<Vec<String>> {
    let mut lx = Lexer::new(input);
    lx.run();
    let mut out = lx.commands;
    out.extend(lx.nested);
    out
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    commands: Vec<Vec<String>>,
    nested: Vec<Vec<String>>,
    current: Vec<String>,
    word: String,
    in_word: bool,
    /// The next word is a redirection target and is dropped.
    skip_next: bool,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            commands: Vec::new(),
            nested: Vec::new(),
            current: Vec::new(),
            word: String::new(),
            in_word: false,
            skip_next: false,
        }
    }

    fn peek(&self, off: usize) -> Option<char> {
        self.chars.get(self.pos + off).copied()
    }

    fn end_word(&mut self) {
        if self.in_word {
            let w = std::mem::take(&mut self.word);
            if self.skip_next {
                self.skip_next = false;
            } else {
                self.current.push(w);
            }
            self.in_word = false;
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        // A redirection with no target (`cmd >`) should not swallow the next command.
        self.skip_next = false;
        if !self.current.is_empty() {
            self.commands.push(std::mem::take(&mut self.current));
        }
    }

    /// Read a balanced `( ... )` body starting after the opening parenthesis.
    fn read_balanced(&mut self) -> String {
        let mut depth = 1;
        let mut body = String::new();
        let mut quote: Option<char> = None;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match quote {
                Some(q) => {
                    if c == '\\' && q == '"' {
                        body.push(c);
                        if let Some(n) = self.peek(0) {
                            body.push(n);
                            self.pos += 1;
                        }
                        continue;
                    }
                    if c == q {
                        quote = None;
                    }
                }
                None => match c {
                    '\'' | '"' => quote = Some(c),
                    '\\' => {
                        body.push(c);
                        if let Some(n) = self.peek(0) {
                            body.push(n);
                            self.pos += 1;
                        }
                        continue;
                    }
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return body;
                        }
                    }
                    _ => {}
                },
            }
            body.push(c);
        }
        body
    }

    fn substitution(&mut self, body: &str) {
        self.nested.extend(split_commands(body));
    }

    /// `$(...)`, `$((...))`, `${...}`, or a plain `$`.
    fn dollar(&mut self) {
        match self.peek(1) {
            Some('(') if self.peek(2) == Some('(') => {
                // Arithmetic expansion: keep as text.
                self.pos += 3;
                let body = self.read_balanced();
                if self.peek(0) == Some(')') {
                    self.pos += 1;
                }
                self.word.push_str("$((");
                self.word.push_str(&body);
                self.word.push_str("))");
            }
            Some('(') => {
                self.pos += 2;
                let body = self.read_balanced();
                self.substitution(&body);
                self.word.push_str("$(");
                self.word.push_str(&body);
                self.word.push(')');
            }
            _ => {
                self.word.push('$');
                self.pos += 1;
            }
        }
        self.in_word = true;
    }

    fn backtick(&mut self) {
        self.pos += 1;
        let mut body = String::new();
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            if c == '\\' {
                if let Some(n) = self.peek(0) {
                    body.push(n);
                    self.pos += 1;
                }
                continue;
            }
            if c == '`' {
                break;
            }
            body.push(c);
        }
        self.substitution(&body);
        self.word.push('`');
        self.word.push_str(&body);
        self.word.push('`');
        self.in_word = true;
    }

    fn redirect(&mut self) {
        // A word made only of digits right before `>` is a file descriptor (`2>`).
        if self.in_word && !self.word.is_empty() && self.word.chars().all(|c| c.is_ascii_digit()) {
            self.word.clear();
            self.in_word = false;
        } else {
            self.end_word();
        }
        let first = self.peek(0);
        self.pos += 1;
        if first == Some('<') && self.peek(0) == Some('(') {
            // Process substitution `<( ... )`.
            self.pos += 1;
            let body = self.read_balanced();
            self.substitution(&body);
            return;
        }
        while matches!(self.peek(0), Some('>') | Some('<') | Some('|')) {
            self.pos += 1;
        }
        if self.peek(0) == Some('&') {
            // `>&2`, `2>&1`, `>&-`: the target is attached.
            self.pos += 1;
            while matches!(self.peek(0), Some(c) if c.is_ascii_digit() || c == '-') {
                self.pos += 1;
            }
            return;
        }
        self.skip_next = true;
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\r' => {
                    self.end_word();
                    self.pos += 1;
                }
                '\n' => {
                    self.end_command();
                    self.pos += 1;
                }
                '#' if !self.in_word => {
                    while let Some(c) = self.peek(0) {
                        if c == '\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                '\'' => {
                    self.in_word = true;
                    self.pos += 1;
                    while let Some(c) = self.peek(0) {
                        self.pos += 1;
                        if c == '\'' {
                            break;
                        }
                        self.word.push(c);
                    }
                }
                '"' => {
                    self.in_word = true;
                    self.pos += 1;
                    while let Some(c) = self.peek(0) {
                        match c {
                            '"' => {
                                self.pos += 1;
                                break;
                            }
                            '\\' => {
                                match self.peek(1) {
                                    Some(n @ ('$' | '`' | '"' | '\\')) => self.word.push(n),
                                    Some('\n') => {}
                                    Some(n) => {
                                        self.word.push('\\');
                                        self.word.push(n);
                                    }
                                    None => self.word.push('\\'),
                                }
                                self.pos += 2;
                            }
                            '$' if self.peek(1) == Some('(') => self.dollar(),
                            '`' => self.backtick(),
                            _ => {
                                self.word.push(c);
                                self.pos += 1;
                            }
                        }
                    }
                }
                '\\' => {
                    match self.peek(1) {
                        Some('\n') => {}
                        Some(n) => {
                            self.word.push(n);
                            self.in_word = true;
                        }
                        None => {}
                    }
                    self.pos += 2;
                }
                '$' => self.dollar(),
                '`' => self.backtick(),
                ';' | '|' | '(' | ')' => {
                    self.end_command();
                    self.pos += 1;
                    if c == '|' && matches!(self.peek(0), Some('|') | Some('&')) {
                        self.pos += 1;
                    }
                    if c == ';' && self.peek(0) == Some(';') {
                        self.pos += 1;
                    }
                }
                '&' => {
                    if self.peek(1) == Some('>') {
                        self.end_word();
                        self.pos += 1;
                        self.redirect();
                    } else {
                        self.end_command();
                        self.pos += if self.peek(1) == Some('&') { 2 } else { 1 };
                    }
                }
                '>' | '<' => self.redirect(),
                _ => {
                    self.word.push(c);
                    self.in_word = true;
                    self.pos += 1;
                }
            }
        }
        self.end_command();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(input: &str) -> Vec<Vec<&'static str>> {
        split_commands(input)
            .into_iter()
            .map(|c| c.into_iter().map(|w| &*Box::leak(w.into_boxed_str())).collect())
            .collect()
    }

    #[test]
    fn operators_split_commands() {
        assert_eq!(
            s("cd app && pip install requests; npm i left-pad | tee log || echo fail & wait"),
            vec![
                vec!["cd", "app"],
                vec!["pip", "install", "requests"],
                vec!["npm", "i", "left-pad"],
                vec!["tee", "log"],
                vec!["echo", "fail"],
                vec!["wait"]
            ]
        );
    }

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(s(r#"pip install "requests>=2,<3" 'flask[async]'"#), vec![vec!["pip", "install", "requests>=2,<3", "flask[async]"]]);
        assert_eq!(s(r#"echo "a \"b\" \$c" d\ e"#), vec![vec!["echo", r#"a "b" $c"#, "d e"]]);
        assert_eq!(s("pip install \\\n  requests"), vec![vec!["pip", "install", "requests"]]);
        assert_eq!(s(r#"pip install pkg"==1.0""#), vec![vec!["pip", "install", "pkg==1.0"]]);
        assert_eq!(s("echo 'it;s && fine'"), vec![vec!["echo", "it;s && fine"]]);
    }

    #[test]
    fn redirections_are_dropped() {
        assert_eq!(
            s("pip install x > /dev/null 2>&1"),
            vec![vec!["pip", "install", "x"]]
        );
        assert_eq!(s("npm i y &>out.log"), vec![vec!["npm", "i", "y"]]);
        assert_eq!(s("pip install z 2> err.txt < in"), vec![vec!["pip", "install", "z"]]);
        assert_eq!(s("cat <<EOF\nhello\nEOF"), vec![vec!["cat"], vec!["hello"], vec!["EOF"]]);
    }

    #[test]
    fn substitutions_are_nested_commands() {
        let out = s("echo $(pip install evil) `npm i bad` \"$(uvx tool)\"");
        assert_eq!(out[0][0], "echo");
        assert!(out.contains(&vec!["pip", "install", "evil"]));
        assert!(out.contains(&vec!["npm", "i", "bad"]));
        assert!(out.contains(&vec!["uvx", "tool"]));
        assert_eq!(s("echo $((1 + 2))"), vec![vec!["echo", "$((1 + 2))"]]);
    }

    #[test]
    fn comments_and_subshells() {
        assert_eq!(
            s("(cd x && npm install a) # pip install b\nyarn add c"),
            vec![vec!["cd", "x"], vec!["npm", "install", "a"], vec!["yarn", "add", "c"]]
        );
        assert_eq!(s("echo a#b"), vec![vec!["echo", "a#b"]]);
        assert!(s("").is_empty());
        assert!(s("   ;; && ").is_empty());
    }
}
