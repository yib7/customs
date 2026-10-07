//! Package-name model (DESIGN.md sections 4.5 and 5, `name_model.json`).
//!
//! Slopsquatting and typosquatting show up in the name alone: a hallucinated or malicious
//! package is often one edit away from a popular one, or wraps a popular name in extra
//! words. This module computes the name features against the shipped popular-package list
//! and scores them with a logistic regression that also sees hashed character n-grams.

use std::collections::{BTreeMap, HashMap, HashSet};

use customs_scan::Ecosystem;
use serde::{Deserialize, Serialize};

use crate::{sigmoid, ModelError};

/// Edit distances are clipped at this value. Anything farther than four edits says nothing
/// about typosquatting, and the cap is what lets the search skip most candidates.
pub const EDIT_DISTANCE_CAP: u32 = 5;

/// Numeric name features in their canonical order.
pub const NUMERIC_NAME_FEATURES: &[&str] = &[
    "len",
    "n_digits",
    "n_hyphens",
    "n_underscores",
    "n_dots",
    "min_edit_distance",
    "is_popular",
    "contains_popular_token",
    "scope_squat",
    "keyboard_typo",
    "char_ngram_score",
];

/// Canonical form of a package name.
///
/// PyPI follows PEP 503: lowercase and collapse every run of `-`, `_`, `.` into one `-`.
/// npm names are case-insensitive in practice but separators are significant, and the
/// scope (`@scope/`) is part of the identity, so we only lowercase.
pub fn normalize(eco: Ecosystem, name: &str) -> String {
    let name = name.trim();
    match eco {
        Ecosystem::Pypi => {
            let mut out = String::with_capacity(name.len());
            let mut in_sep = false;
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !in_sep {
                        out.push('-');
                    }
                    in_sep = true;
                } else {
                    out.extend(c.to_lowercase());
                    in_sep = false;
                }
            }
            out
        }
        Ecosystem::Npm => name.to_lowercase(),
    }
}

/// Split an npm name into `(Some(scope), bare)` or `(None, name)`. The scope keeps no `@`.
pub fn split_npm_scope(name: &str) -> (Option<&str>, &str) {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, bare)) = rest.split_once('/') {
            return (Some(scope), bare);
        }
    }
    (None, name)
}

/// Collapse separator runs to `-` so "foo_bar" and "foo.bar" match "foo-bar" in the token
/// check regardless of ecosystem.
fn sep_normalize(s: &str) -> String {
    normalize(Ecosystem::Pypi, s)
}

/// FNV-1a, 32-bit.
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Hashed character n-gram buckets of `^name$`, one entry per occurrence.
pub fn ngram_buckets(normalized: &str, n_min: usize, n_max: usize, n_buckets: u32) -> Vec<u32> {
    let chars: Vec<char> = std::iter::once('^')
        .chain(normalized.chars())
        .chain(std::iter::once('$'))
        .collect();
    let mut out = Vec::new();
    let mut buf = String::new();
    for n in n_min.max(1)..=n_max {
        if n > chars.len() {
            break;
        }
        for w in chars.windows(n) {
            buf.clear();
            buf.extend(w.iter());
            out.push(fnv1a32(buf.as_bytes()) % n_buckets);
        }
    }
    out
}

/// Optimal string alignment distance (restricted Damerau-Levenshtein: adjacent
/// transpositions count as one edit, no substring is edited twice), bounded by `limit`.
/// Returns `limit + 1` as soon as the distance is known to exceed `limit`.
pub fn osa_distance_bounded(a: &[char], b: &[char], limit: u32, scratch: &mut Scratch) -> u32 {
    let (n, m) = (a.len(), b.len());
    if n.abs_diff(m) as u32 > limit {
        return limit + 1;
    }
    if n == 0 || m == 0 {
        return (n.max(m) as u32).min(limit + 1);
    }
    scratch.prepare(m + 1);
    let Scratch { prev2, prev, cur } = scratch;
    for (j, v) in prev.iter_mut().enumerate() {
        *v = j as u32;
    }
    for i in 1..=n {
        cur[0] = i as u32;
        let mut row_min = cur[0];
        for j in 1..=m {
            let cost = u32::from(a[i - 1] != b[j - 1]);
            let mut d = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(prev2[j - 2] + 1);
            }
            cur[j] = d;
            row_min = row_min.min(d);
        }
        // Row minima never decrease in OSA, so once a whole row is over the limit the
        // final distance is too.
        if row_min > limit {
            return limit + 1;
        }
        std::mem::swap(prev2, prev);
        std::mem::swap(prev, cur);
    }
    prev[m].min(limit + 1)
}

/// Character counts over 32 classes (letters, digits, separators, everything else).
type Hist = [u8; 32];

fn hist(chars: &[char]) -> Hist {
    let mut h = [0u8; 32];
    for &c in chars {
        let i = match c {
            'a'..='z' => c as usize - 'a' as usize,
            '0'..='9' => 26 + (c as usize - '0' as usize) % 3,
            '-' | '_' | '.' => 29,
            '/' | '@' => 30,
            _ => 31,
        };
        h[i] = h[i].saturating_add(1);
    }
    h
}

/// Every edit changes the class histogram by at most 2 in L1 norm (a substitution moves one
/// count, an insertion or deletion changes one count, a transposition changes nothing), so
/// `ceil(L1 / 2)` never exceeds the true distance. It rejects most candidates for the
/// price of 32 byte subtractions.
fn hist_lower_bound(a: &Hist, b: &Hist) -> u32 {
    let l1: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| x.abs_diff(*y) as u32)
        .sum();
    l1.div_ceil(2)
}

/// Reusable DP rows so scoring a name does not allocate per candidate.
#[derive(Default, Debug)]
pub struct Scratch {
    prev2: Vec<u32>,
    prev: Vec<u32>,
    cur: Vec<u32>,
}

impl Scratch {
    fn prepare(&mut self, len: usize) {
        for v in [&mut self.prev2, &mut self.prev, &mut self.cur] {
            v.clear();
            v.resize(len, 0);
        }
    }
}

/// Unrestricted OSA distance (no bound). Convenience for tests and tools.
pub fn osa_distance(a: &str, b: &str) -> u32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let limit = (a.len().max(b.len())) as u32;
    osa_distance_bounded(&a, &b, limit, &mut Scratch::default())
}

const KEYBOARD_ROWS: [&str; 4] = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

fn key_pos(c: char) -> Option<(i32, i32)> {
    KEYBOARD_ROWS.iter().enumerate().find_map(|(r, row)| {
        row.chars()
            .position(|k| k == c)
            .map(|col| (r as i32, col as i32))
    })
}

/// True when `a` and `b` are neighbours on a QWERTY keyboard. Each row is offset half a
/// key to the right of the row above, so key (r, c) touches (r + 1, c - 1) and (r + 1, c).
pub fn keyboard_adjacent(a: char, b: char) -> bool {
    let (Some((ra, ca)), Some((rb, cb))) = (key_pos(a), key_pos(b)) else {
        return false;
    };
    if ra == rb {
        return (ca - cb).abs() == 1;
    }
    let (upper, lower) = if ra < rb {
        ((ra, ca), (rb, cb))
    } else {
        ((rb, cb), (ra, ca))
    };
    lower.0 - upper.0 == 1 && (lower.1 == upper.1 || lower.1 == upper.1 - 1)
}

/// The popular-package list of one ecosystem, indexed for fast nearest-name search.
#[derive(Debug, Clone)]
pub struct PopularIndex {
    eco: Ecosystem,
    /// Normalized names in popularity order (index = rank).
    names: Vec<String>,
    chars: Vec<Vec<char>>,
    /// Character histograms for a cheap lower bound on the edit distance.
    hists: Vec<Hist>,
    rank: HashMap<String, usize>,
    /// Candidate ranks grouped by character length; a name of length L can only be within
    /// distance d of names whose length is in [L - d, L + d].
    by_len: Vec<Vec<u32>>,
    /// Separator-normalized names (and npm bare names) for the token-containment check.
    token_names: HashSet<String>,
    /// npm: bare name to the scopes of popular scoped packages with that bare name.
    scoped_bare: HashMap<String, Vec<String>>,
    /// npm: scopes that appear in the popular list.
    scopes: Vec<String>,
}

impl PopularIndex {
    /// Parse a list with one name per line; blank lines and `#` comments are ignored.
    /// Order is popularity rank, which breaks ties when two names are equally close.
    pub fn from_text(eco: Ecosystem, text: &str) -> Self {
        Self::new(
            eco,
            text.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim())
                .filter(|l| !l.is_empty()),
        )
    }

    pub fn new<'a>(eco: Ecosystem, names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut idx = PopularIndex {
            eco,
            names: Vec::new(),
            chars: Vec::new(),
            hists: Vec::new(),
            rank: HashMap::new(),
            by_len: Vec::new(),
            token_names: HashSet::new(),
            scoped_bare: HashMap::new(),
            scopes: Vec::new(),
        };
        for raw in names {
            let n = normalize(eco, raw);
            if n.is_empty() || idx.rank.contains_key(&n) {
                continue;
            }
            let r = idx.names.len();
            let chars: Vec<char> = n.chars().collect();
            if idx.by_len.len() <= chars.len() {
                idx.by_len.resize(chars.len() + 1, Vec::new());
            }
            idx.by_len[chars.len()].push(r as u32);
            let (scope, bare) = split_npm_scope(&n);
            if eco == Ecosystem::Npm {
                if let Some(s) = scope {
                    idx.scoped_bare
                        .entry(bare.to_string())
                        .or_default()
                        .push(s.to_string());
                    if !idx.scopes.iter().any(|x| x == s) {
                        idx.scopes.push(s.to_string());
                    }
                }
            }
            idx.token_names.insert(sep_normalize(bare));
            idx.rank.insert(n.clone(), r);
            idx.names.push(n);
            idx.hists.push(hist(&chars));
            idx.chars.push(chars);
        }
        idx
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.eco
    }

    pub fn contains(&self, normalized: &str) -> bool {
        self.rank.contains_key(normalized)
    }

    /// Nearest popular name other than `normalized` itself: `(distance, rank)` with the
    /// distance clipped at [`EDIT_DISTANCE_CAP`]. Ties go to the more popular name.
    pub fn nearest(&self, normalized: &str, scratch: &mut Scratch) -> Option<(u32, usize)> {
        let q: Vec<char> = normalized.chars().collect();
        let qh = hist(&q);
        let mut best: Option<(u32, usize)> = None;
        let cap = EDIT_DISTANCE_CAP;
        // Only distances below the cap are searched; everything else is clipped to the cap
        // and resolved by the fallback below. Visit length buckets by increasing length
        // difference: a bucket whose difference exceeds the best distance so far cannot
        // contain a better (or tied) candidate.
        for diff in 0..cap as usize {
            let bound = best.map(|b| b.0).unwrap_or(cap - 1);
            if diff as u32 > bound {
                break;
            }
            let lens = if diff == 0 {
                [Some(q.len()), None]
            } else {
                [q.len().checked_sub(diff), Some(q.len() + diff)]
            };
            for len in lens.into_iter().flatten() {
                let Some(bucket) = self.by_len.get(len) else {
                    continue;
                };
                for &r in bucket {
                    let r = r as usize;
                    let cand = &self.chars[r];
                    if *cand == q {
                        continue;
                    }
                    let limit = best.map(|b| b.0).unwrap_or(cap - 1);
                    if hist_lower_bound(&qh, &self.hists[r]) > limit {
                        continue;
                    }
                    let d = osa_distance_bounded(&q, cand, limit, scratch);
                    if d > limit {
                        continue;
                    }
                    match best {
                        Some((bd, br)) if (d, r) >= (bd, br) => {}
                        _ => best = Some((d, r)),
                    }
                }
            }
        }
        best.or_else(|| {
            // Nothing within the cap: report the cap and the most popular name so the
            // feature is always defined.
            (0..self.names.len())
                .find(|&r| self.names[r] != normalized)
                .map(|r| (cap, r))
        })
    }

    /// A popular name that appears as a proper token run of `normalized`, e.g. `requests`
    /// inside `requests-auth-helper`. Returns the longest match.
    fn contained_token(&self, normalized: &str) -> Option<String> {
        let bare = match self.eco {
            Ecosystem::Npm => split_npm_scope(normalized).1,
            Ecosystem::Pypi => normalized,
        };
        let tokens: Vec<&str> = bare
            .split(['-', '_', '.'])
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.len() < 2 {
            return None;
        }
        let mut found: Option<String> = None;
        for i in 0..tokens.len() {
            for j in i + 1..=tokens.len() {
                if j - i == tokens.len() {
                    continue;
                }
                let joined = tokens[i..j].join("-");
                if joined.chars().count() < 3 || !self.token_names.contains(&joined) {
                    continue;
                }
                if found.as_ref().is_none_or(|f| joined.len() > f.len()) {
                    found = Some(joined);
                }
            }
        }
        found
    }

    /// npm only: a scoped name whose scope differs from a popular scoped package with the
    /// same bare name, or whose scope is one or two edits from a popular scope.
    fn scope_squat(&self, normalized: &str, scratch: &mut Scratch) -> Option<String> {
        if self.eco != Ecosystem::Npm {
            return None;
        }
        let (Some(scope), bare) = split_npm_scope(normalized) else {
            return None;
        };
        if let Some(scopes) = self.scoped_bare.get(bare) {
            if let Some(s) = scopes.iter().find(|s| s.as_str() != scope) {
                return Some(format!("@{s}/{bare}"));
            }
        }
        let q: Vec<char> = scope.chars().collect();
        if q.len() < 3 {
            return None;
        }
        let mut best: Option<(u32, &str)> = None;
        for s in &self.scopes {
            if s == scope {
                return None;
            }
            let c: Vec<char> = s.chars().collect();
            let d = osa_distance_bounded(&q, &c, 2, scratch);
            if d <= 2 && best.is_none_or(|(bd, _)| d < bd) {
                best = Some((d, s));
            }
        }
        best.map(|(_, s)| format!("@{s}"))
    }
}

/// Every name feature of DESIGN.md 4.5 for one name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NameFeatures {
    pub normalized: String,
    pub len: u32,
    pub n_digits: u32,
    pub n_hyphens: u32,
    pub n_underscores: u32,
    pub n_dots: u32,
    pub min_edit_distance: u32,
    pub nearest_popular: Option<String>,
    pub is_popular: bool,
    /// The popular name found as a token run, when `contains_popular_token` is 1.
    pub contains_popular_token: Option<String>,
    /// The popular scoped package or scope being imitated, when `scope_squat` is 1.
    pub scope_squat: Option<String>,
    pub keyboard_typo: bool,
    /// The n-gram part of the name logit (sum of bucket weights).
    pub char_ngram_score: f64,
}

impl NameFeatures {
    /// Numeric value of a named feature, `None` for unknown names.
    pub fn get(&self, feature: &str) -> Option<f64> {
        Some(match feature {
            "len" => self.len as f64,
            "n_digits" => self.n_digits as f64,
            "n_hyphens" => self.n_hyphens as f64,
            "n_underscores" => self.n_underscores as f64,
            "n_dots" => self.n_dots as f64,
            "min_edit_distance" => self.min_edit_distance as f64,
            "is_popular" => f64::from(u8::from(self.is_popular)),
            "contains_popular_token" => f64::from(u8::from(self.contains_popular_token.is_some())),
            "scope_squat" => f64::from(u8::from(self.scope_squat.is_some())),
            "keyboard_typo" => f64::from(u8::from(self.keyboard_typo)),
            "char_ngram_score" => self.char_ngram_score,
            _ => return None,
        })
    }

    /// A one-line explanation of the strongest name signal, if any.
    pub fn explanation(&self) -> Option<String> {
        if self.is_popular {
            return None;
        }
        let near = self.nearest_popular.as_deref().unwrap_or("");
        if self.keyboard_typo {
            return Some(format!(
                "1 edit (adjacent-key typo) from popular package '{near}'"
            ));
        }
        if (1..=2).contains(&self.min_edit_distance) {
            let d = self.min_edit_distance;
            let s = if d == 1 { "edit" } else { "edits" };
            return Some(format!("{d} {s} from popular package '{near}'"));
        }
        if let Some(s) = &self.scope_squat {
            return Some(format!("scope imitates popular npm scope or package '{s}'"));
        }
        if let Some(t) = &self.contains_popular_token {
            return Some(format!(
                "wraps popular package name '{t}' in extra words"
            ));
        }
        None
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum NgramWeights {
    Dense(Vec<f64>),
    /// Sparse `{"bucket": weight}`; exporters may use it when most buckets are zero.
    Sparse(BTreeMap<String, f64>),
}

#[derive(Debug, Clone, Deserialize)]
struct RawNameModel {
    #[serde(default)]
    feature_names: Vec<String>,
    #[serde(default)]
    feature_weights: Vec<f64>,
    #[serde(default)]
    feature_mean: Option<Vec<f64>>,
    #[serde(default)]
    feature_scale: Option<Vec<f64>>,
    n_buckets: u32,
    #[serde(default = "one")]
    ngram_min: usize,
    #[serde(default = "four")]
    ngram_max: usize,
    weights: NgramWeights,
    #[serde(default)]
    bias: f64,
}

fn one() -> usize {
    1
}
fn four() -> usize {
    4
}

/// Logistic regression over name features and hashed character n-grams.
#[derive(Debug, Clone)]
pub struct NameModel {
    feature_names: Vec<String>,
    feature_weights: Vec<f64>,
    feature_mean: Vec<f64>,
    feature_scale: Vec<f64>,
    n_buckets: u32,
    ngram_min: usize,
    ngram_max: usize,
    ngram_weights: Vec<f64>,
    bias: f64,
}

/// Output of the name model for one name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NameScore {
    pub logit: f64,
    pub prob: f64,
    pub features: NameFeatures,
    pub explanation: Option<String>,
    /// `(feature, value, logit contribution)`, largest positive first. The n-gram part
    /// appears as `char_ngram_score`.
    pub contributions: Vec<(String, f64, f64)>,
}

impl NameModel {
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        const WHAT: &str = "name_model";
        let raw: RawNameModel =
            serde_json::from_str(text).map_err(|e| ModelError::parse(WHAT, e))?;
        let nf = raw.feature_names.len();
        if raw.feature_weights.len() != nf {
            return Err(ModelError::invalid(
                WHAT,
                format!(
                    "{} feature_names but {} feature_weights",
                    nf,
                    raw.feature_weights.len()
                ),
            ));
        }
        for f in &raw.feature_names {
            if f == "char_ngram_score" || !NUMERIC_NAME_FEATURES.contains(&f.as_str()) {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("feature '{f}' is not a numeric name feature (char_ngram_score is implicit)"),
                ));
            }
        }
        let mean = raw.feature_mean.unwrap_or_else(|| vec![0.0; nf]);
        let scale = raw.feature_scale.unwrap_or_else(|| vec![1.0; nf]);
        if mean.len() != nf || scale.len() != nf {
            return Err(ModelError::invalid(
                WHAT,
                "feature_mean and feature_scale must match feature_names",
            ));
        }
        if scale.iter().any(|s| *s == 0.0 || !s.is_finite()) {
            return Err(ModelError::invalid(WHAT, "feature_scale must be finite and non-zero"));
        }
        if raw.n_buckets == 0 || raw.n_buckets > (1 << 24) {
            return Err(ModelError::invalid(WHAT, "n_buckets must be in 1..=2^24"));
        }
        if raw.ngram_min == 0 || raw.ngram_min > raw.ngram_max {
            return Err(ModelError::invalid(WHAT, "need 1 <= ngram_min <= ngram_max"));
        }
        let ngram_weights = match raw.weights {
            NgramWeights::Dense(w) => {
                if w.len() != raw.n_buckets as usize {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("weights has {} entries, n_buckets is {}", w.len(), raw.n_buckets),
                    ));
                }
                w
            }
            NgramWeights::Sparse(m) => {
                let mut w = vec![0.0; raw.n_buckets as usize];
                for (k, v) in m {
                    let i: usize = k.parse().map_err(|_| {
                        ModelError::invalid(WHAT, format!("weights key '{k}' is not a bucket index"))
                    })?;
                    if i >= w.len() {
                        return Err(ModelError::invalid(WHAT, format!("bucket {i} out of range")));
                    }
                    w[i] = v;
                }
                w
            }
        };
        Ok(Self {
            feature_names: raw.feature_names,
            feature_weights: raw.feature_weights,
            feature_mean: mean,
            feature_scale: scale,
            n_buckets: raw.n_buckets,
            ngram_min: raw.ngram_min,
            ngram_max: raw.ngram_max,
            ngram_weights,
            bias: raw.bias,
        })
    }

    pub fn n_buckets(&self) -> u32 {
        self.n_buckets
    }

    /// Sum of n-gram weights for a normalized name.
    pub fn ngram_logit(&self, normalized: &str) -> f64 {
        ngram_buckets(normalized, self.ngram_min, self.ngram_max, self.n_buckets)
            .into_iter()
            .map(|b| self.ngram_weights[b as usize])
            .sum()
    }

    /// Compute all features for `name` (n-gram score included).
    pub fn features(
        &self,
        eco: Ecosystem,
        name: &str,
        popular: Option<&PopularIndex>,
        scratch: &mut Scratch,
    ) -> NameFeatures {
        let mut f = compute_features(eco, name, popular, scratch);
        f.char_ngram_score = self.ngram_logit(&f.normalized);
        f
    }

    pub fn score(&self, eco: Ecosystem, name: &str, popular: Option<&PopularIndex>) -> NameScore {
        let mut scratch = Scratch::default();
        let features = self.features(eco, name, popular, &mut scratch);
        self.score_features(features)
    }

    /// Score precomputed features.
    pub fn score_features(&self, features: NameFeatures) -> NameScore {
        let mut contributions = Vec::with_capacity(self.feature_names.len() + 1);
        let mut logit = self.bias + features.char_ngram_score;
        for (i, name) in self.feature_names.iter().enumerate() {
            let x = features.get(name).unwrap_or(0.0);
            let c = self.feature_weights[i] * (x - self.feature_mean[i]) / self.feature_scale[i];
            logit += c;
            contributions.push((name.clone(), x, c));
        }
        contributions.push((
            "char_ngram_score".to_string(),
            features.char_ngram_score,
            features.char_ngram_score,
        ));
        contributions.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        let explanation = features.explanation();
        NameScore {
            logit,
            prob: sigmoid(logit),
            features,
            explanation,
            contributions,
        }
    }
}

/// Name features that do not depend on model weights (`char_ngram_score` is left at 0).
pub fn compute_features(
    eco: Ecosystem,
    name: &str,
    popular: Option<&PopularIndex>,
    scratch: &mut Scratch,
) -> NameFeatures {
    let normalized = normalize(eco, name);
    let count = |pred: fn(char) -> bool| normalized.chars().filter(|c| pred(*c)).count() as u32;
    let mut f = NameFeatures {
        len: normalized.chars().count() as u32,
        n_digits: count(|c| c.is_ascii_digit()),
        n_hyphens: count(|c| c == '-'),
        n_underscores: count(|c| c == '_'),
        n_dots: count(|c| c == '.'),
        min_edit_distance: EDIT_DISTANCE_CAP,
        nearest_popular: None,
        is_popular: false,
        contains_popular_token: None,
        scope_squat: None,
        keyboard_typo: false,
        char_ngram_score: 0.0,
        normalized,
    };
    let Some(pop) = popular else {
        return f;
    };
    f.is_popular = pop.contains(&f.normalized);
    if let Some((d, r)) = pop.nearest(&f.normalized, scratch) {
        f.min_edit_distance = d;
        let near = &pop.names[r];
        f.nearest_popular = Some(near.clone());
        if d == 1 {
            f.keyboard_typo = is_keyboard_substitution(&f.normalized, near);
        }
    }
    if !f.is_popular {
        f.contains_popular_token = pop.contained_token(&f.normalized);
        f.scope_squat = pop.scope_squat(&f.normalized, scratch);
    }
    f
}

/// Same length, exactly one differing position, and the two characters are adjacent keys.
fn is_keyboard_substitution(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len() != b.len() {
        return false;
    }
    let diffs: Vec<(char, char)> = a
        .iter()
        .zip(&b)
        .filter(|(x, y)| x != y)
        .map(|(x, y)| (*x, *y))
        .collect();
    diffs.len() == 1 && keyboard_adjacent(diffs[0].0, diffs[0].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pypi() -> PopularIndex {
        PopularIndex::new(
            Ecosystem::Pypi,
            [
                "requests",
                "numpy",
                "python-dateutil",
                "urllib3",
                "Flask",
                "setuptools",
                "six",
            ],
        )
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize(Ecosystem::Pypi, "Foo__Bar.baz-_qux"), "foo-bar-baz-qux");
        assert_eq!(normalize(Ecosystem::Pypi, "  Django "), "django");
        assert_eq!(normalize(Ecosystem::Npm, "@Babel/Core"), "@babel/core");
        assert_eq!(normalize(Ecosystem::Npm, "lodash.merge"), "lodash.merge");
    }

    #[test]
    fn fnv_known_values() {
        // Reference values of FNV-1a 32-bit.
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        assert_eq!(fnv1a32(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn ngrams_include_boundaries() {
        // "^ab$": 4 unigrams, 3 bigrams.
        assert_eq!(ngram_buckets("ab", 1, 2, 1 << 20).len(), 7);
        let b = ngram_buckets("ab", 1, 1, 1 << 30);
        assert_eq!(b[0], fnv1a32(b"^") % (1 << 30));
        assert_eq!(ngram_buckets("a", 1, 9, 16).len(), 3 + 2 + 1);
    }

    #[test]
    fn osa_distance_cases() {
        assert_eq!(osa_distance("requests", "requests"), 0);
        assert_eq!(osa_distance("reqeusts", "requests"), 1);
        assert_eq!(osa_distance("requets", "requests"), 1);
        assert_eq!(osa_distance("requestss", "requests"), 1);
        assert_eq!(osa_distance("kitten", "sitting"), 3);
        assert_eq!(osa_distance("ca", "abc"), 3); // OSA, not unrestricted DL (which is 2)
        assert_eq!(osa_distance("", "abc"), 3);
        let mut s = Scratch::default();
        let a: Vec<char> = "abcdefgh".chars().collect();
        let b: Vec<char> = "hgfedcba".chars().collect();
        assert_eq!(osa_distance_bounded(&a, &b, 2, &mut s), 3);
    }

    #[test]
    fn keyboard() {
        assert!(keyboard_adjacent('q', 'w'));
        assert!(keyboard_adjacent('w', 'a'));
        assert!(keyboard_adjacent('s', 'w'));
        assert!(keyboard_adjacent('n', 'm'));
        assert!(!keyboard_adjacent('q', 'p'));
        assert!(!keyboard_adjacent('a', 'a'));
        assert!(keyboard_adjacent('2', 'q'));
    }

    #[test]
    fn features_for_typosquat() {
        let p = pypi();
        let mut s = Scratch::default();
        let f = compute_features(Ecosystem::Pypi, "reqeusts", Some(&p), &mut s);
        assert_eq!(f.min_edit_distance, 1);
        assert_eq!(f.nearest_popular.as_deref(), Some("requests"));
        assert!(!f.keyboard_typo);
        assert_eq!(
            f.explanation().unwrap(),
            "1 edit from popular package 'requests'"
        );

        let f = compute_features(Ecosystem::Pypi, "requezts", Some(&p), &mut s);
        assert!(f.keyboard_typo);

        let f = compute_features(Ecosystem::Pypi, "Requests", Some(&p), &mut s);
        assert!(f.is_popular);
        assert!(f.min_edit_distance >= 1);
        assert_eq!(f.explanation(), None);

        let f = compute_features(Ecosystem::Pypi, "requests_auth_helper", Some(&p), &mut s);
        assert_eq!(f.contains_popular_token.as_deref(), Some("requests"));
        assert_eq!(f.n_hyphens, 2);
        let f = compute_features(Ecosystem::Pypi, "python-dateutil-ext", Some(&p), &mut s);
        assert_eq!(f.contains_popular_token.as_deref(), Some("python-dateutil"));
        let f = compute_features(Ecosystem::Pypi, "zzzzzzzzzzzzzzzzz", Some(&p), &mut s);
        assert_eq!(f.min_edit_distance, EDIT_DISTANCE_CAP);
        assert_eq!(f.explanation(), None);
    }

    #[test]
    fn npm_scope_squat() {
        let p = PopularIndex::new(
            Ecosystem::Npm,
            ["react", "@babel/core", "@types/node", "lodash"],
        );
        let mut s = Scratch::default();
        let f = compute_features(Ecosystem::Npm, "@babel-js/core", Some(&p), &mut s);
        assert_eq!(f.scope_squat.as_deref(), Some("@babel/core"));
        let f = compute_features(Ecosystem::Npm, "@bable/parser", Some(&p), &mut s);
        assert_eq!(f.scope_squat.as_deref(), Some("@babel"));
        let f = compute_features(Ecosystem::Npm, "@babel/core", Some(&p), &mut s);
        assert!(f.is_popular);
        assert!(f.scope_squat.is_none());
        let f = compute_features(Ecosystem::Npm, "@acme/thing", Some(&p), &mut s);
        assert!(f.scope_squat.is_none());
    }

    #[test]
    fn ties_prefer_popular() {
        let p = PopularIndex::new(Ecosystem::Pypi, ["abcd", "abce"]);
        let mut s = Scratch::default();
        assert_eq!(p.nearest("abcf", &mut s), Some((1, 0)));
    }

    #[test]
    fn nearest_matches_brute_force() {
        let names: Vec<String> = (0..400)
            .map(|i| format!("pkg{}{}", i * 7919 % 1000, ["a", "bb", "ccc", "dddd"][i % 4]))
            .collect();
        let p = PopularIndex::new(Ecosystem::Pypi, names.iter().map(|s| s.as_str()));
        let mut s = Scratch::default();
        for q in ["pkg123a", "pkg12bb", "pkgx", "pkg999dddd", "zzz", "pkg7919a"] {
            let got = p.nearest(q, &mut s).unwrap();
            let mut best = (EDIT_DISTANCE_CAP, usize::MAX);
            for (r, n) in names.iter().enumerate() {
                if n == q {
                    continue;
                }
                let d = osa_distance(q, n).min(EDIT_DISTANCE_CAP);
                if (d, r) < best {
                    best = (d, r);
                }
            }
            assert_eq!(got, best, "{q}");
        }
    }
}
