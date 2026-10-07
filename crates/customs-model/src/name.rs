//! Package-name model (DESIGN.md sections 4.5 and 5, `name_model.json`, format
//! `customs-name-lr-v1`).
//!
//! Slopsquatting and typosquatting show up in the name alone: a hallucinated or malicious
//! package is often one edit away from a popular one, or wraps a popular name in extra
//! words. This module computes the name features against the popular-package list of the
//! ecosystem and scores them with a logistic regression that also sees hashed character
//! n-grams. Every definition here mirrors `python/customs_ml` exactly; the parity fixtures
//! in `tests/fixtures` check it.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine as _;
use customs_scan::Ecosystem;
use serde::{Deserialize, Serialize};

use crate::{sigmoid, ModelError};

/// Numeric features of `customs-name-lr-v1`, in their canonical order.
pub const NUMERIC_NAME_FEATURES: &[&str] = &[
    "len",
    "n_digits",
    "n_hyphens",
    "n_underscores",
    "n_dots",
    "has_scope",
    "is_popular",
    "dist1",
    "dist2",
    "dist3",
    "contains_popular_token",
    "digit_suffix",
];

/// Popular names shorter than this never count as a wrapped token ("js", "py", "six").
const MIN_TOKEN_CHARS: usize = 4;

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

/// The part of a name after an npm scope (`@scope/x` gives `x`); the name itself otherwise.
pub fn bare(name: &str) -> &str {
    split_npm_scope(name).1
}

/// Distinct n-gram buckets of `^name$`, sorted. Each bucket counts once.
pub fn distinct_buckets(normalized: &str, n_min: usize, n_max: usize, n_buckets: u32) -> Vec<u32> {
    let mut b = ngram_buckets(normalized, n_min, n_max, n_buckets);
    b.sort_unstable();
    b.dedup();
    b
}

/// The popular-package list of one ecosystem, indexed for fast nearest-name search.
///
/// Distances are measured between bare names, so `@types/node` is compared as `node`.
#[derive(Debug, Clone)]
pub struct PopularIndex {
    /// Normalized full names, in file order (most popular first).
    names: Vec<String>,
    full: HashSet<String>,
    /// Distinct bare names with the rank of the first full name that has them.
    bares: Vec<(Vec<char>, Hist, usize)>,
    bare_set: HashMap<String, usize>,
    /// Candidate indexes into `bares` by character length; a name of length L is within
    /// distance d only of names whose length is in [L - d, L + d].
    by_len: Vec<Vec<u32>>,
    /// Bare names of at least [`MIN_TOKEN_CHARS`] characters.
    long_pop: HashSet<String>,
}

impl PopularIndex {
    /// Parse a list with one name per line; blank lines and `#` comments are ignored.
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
            names: Vec::new(),
            full: HashSet::new(),
            bares: Vec::new(),
            bare_set: HashMap::new(),
            by_len: Vec::new(),
            long_pop: HashSet::new(),
        };
        for raw in names {
            let n = normalize(eco, raw);
            if n.is_empty() || !idx.full.insert(n.clone()) {
                continue;
            }
            let rank = idx.names.len();
            let b = bare(&n).to_string();
            if !idx.bare_set.contains_key(&b) {
                let chars: Vec<char> = b.chars().collect();
                if chars.len() >= MIN_TOKEN_CHARS {
                    idx.long_pop.insert(b.clone());
                }
                if idx.by_len.len() <= chars.len() {
                    idx.by_len.resize(chars.len() + 1, Vec::new());
                }
                idx.by_len[chars.len()].push(idx.bares.len() as u32);
                idx.bare_set.insert(b, idx.bares.len());
                let h = hist(&chars);
                idx.bares.push((chars, h, rank));
            }
            idx.names.push(n);
        }
        idx
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn contains(&self, normalized: &str) -> bool {
        self.full.contains(normalized)
    }

    /// Smallest OSA distance from `bare_name` to a different popular bare name, as
    /// `(distance, nearest full name)`. Distances above `max_distance` are reported as
    /// `max_distance + 1` with no name. Ties go to the more popular name.
    pub fn nearest(
        &self,
        bare_name: &str,
        max_distance: u32,
        scratch: &mut Scratch,
    ) -> (u32, Option<&str>) {
        let q: Vec<char> = bare_name.chars().collect();
        let qh = hist(&q);
        // (distance, rank)
        let mut best: Option<(u32, usize)> = None;
        // Visit length buckets by increasing length difference; once the difference exceeds
        // the best distance found, no later bucket can contain a closer or tied name.
        for diff in 0..=max_distance as usize {
            let bound = best.map(|b| b.0).unwrap_or(max_distance);
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
                for &i in bucket {
                    let (chars, h, rank) = &self.bares[i as usize];
                    if *chars == q {
                        continue;
                    }
                    let limit = best.map(|b| b.0).unwrap_or(max_distance);
                    if hist_lower_bound(&qh, h) > limit {
                        continue;
                    }
                    let d = osa_distance_bounded(&q, chars, limit, scratch);
                    if d > limit {
                        continue;
                    }
                    if best.is_none_or(|(bd, br)| (d, *rank) < (bd, br)) {
                        best = Some((d, *rank));
                    }
                }
            }
        }
        match best {
            Some((d, r)) => (d, Some(self.names[r].as_str())),
            None => (max_distance + 1, None),
        }
    }

    /// First token of `bare_name` that is a long popular bare name, when the name has
    /// several tokens and is not itself a long popular name.
    fn wrapped_token(&self, bare_name: &str) -> Option<String> {
        let tokens: Vec<&str> = bare_name
            .split(['-', '_', '.'])
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.len() < 2 || self.long_pop.contains(bare_name) {
            return None;
        }
        tokens
            .into_iter()
            .find(|t| self.long_pop.contains(*t))
            .map(str::to_string)
    }
}

/// Every name feature for one name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NameFeatures {
    pub normalized: String,
    pub bare: String,
    pub len: u32,
    pub n_digits: u32,
    pub n_hyphens: u32,
    pub n_underscores: u32,
    pub n_dots: u32,
    pub has_scope: bool,
    pub is_popular: bool,
    /// OSA distance to the nearest other popular name, `max_distance + 1` when farther.
    pub distance: u32,
    pub nearest_popular: Option<String>,
    /// The popular name found as a token, when `contains_popular_token` is 1.
    pub contains_popular_token: Option<String>,
    pub digit_suffix: bool,
    /// Explanation only (not a model input): the nearest name is one adjacent-key typo away.
    pub keyboard_typo: bool,
    /// The n-gram part of the logit (sum of weights over distinct buckets).
    pub char_ngram_score: f64,
}

fn b(v: bool) -> f64 {
    f64::from(u8::from(v))
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
            "has_scope" => b(self.has_scope),
            "is_popular" => b(self.is_popular),
            "dist1" => b(self.distance == 1),
            "dist2" => b(self.distance == 2),
            "dist3" => b(self.distance == 3),
            "contains_popular_token" => b(self.contains_popular_token.is_some()),
            "digit_suffix" => b(self.digit_suffix),
            "min_edit_distance" => self.distance as f64,
            "keyboard_typo" => b(self.keyboard_typo),
            "char_ngram_score" => self.char_ngram_score,
            _ => return None,
        })
    }

    /// The feature behind [`NameFeatures::explanation`] and its value.
    pub fn explanation_feature(&self) -> Option<(&'static str, f64)> {
        if self.is_popular {
            None
        } else if self.distance == 1 {
            Some(("dist1", 1.0))
        } else if self.distance == 2 {
            Some(("dist2", 1.0))
        } else if self.contains_popular_token.is_some() {
            Some(("contains_popular_token", 1.0))
        } else {
            None
        }
    }

    /// A one-line explanation of the strongest name signal, if any.
    pub fn explanation(&self) -> Option<String> {
        if self.is_popular {
            return None;
        }
        if let (d @ 1..=2, Some(near)) = (self.distance, &self.nearest_popular) {
            let typo = if self.keyboard_typo {
                " (adjacent-key typo)"
            } else {
                ""
            };
            let s = if d == 1 { "edit" } else { "edits" };
            return Some(format!("{d} {s}{typo} from popular package '{near}'"));
        }
        self.contains_popular_token
            .as_ref()
            .map(|t| format!("wraps popular name '{t}' in extra words"))
    }
}

/// Compute the features of `name` (`char_ngram_score` is left at 0).
pub fn compute_features(
    eco: Ecosystem,
    name: &str,
    popular: &PopularIndex,
    max_distance: u32,
    scratch: &mut Scratch,
) -> NameFeatures {
    let normalized = normalize(eco, name);
    let bare_name = bare(&normalized).to_string();
    let count = |c: char| bare_name.chars().filter(|x| *x == c).count() as u32;
    let (distance, nearest) = popular.nearest(&bare_name, max_distance, scratch);
    let nearest = nearest.map(str::to_string);
    let keyboard_typo = distance == 1
        && nearest
            .as_deref()
            .is_some_and(|n| is_keyboard_substitution(&bare_name, bare(n)));
    NameFeatures {
        len: bare_name.chars().count() as u32,
        n_digits: bare_name.chars().filter(|c| c.is_ascii_digit()).count() as u32,
        n_hyphens: count('-'),
        n_underscores: count('_'),
        n_dots: count('.'),
        has_scope: normalized.starts_with('@'),
        is_popular: popular.contains(&normalized),
        distance,
        nearest_popular: nearest,
        contains_popular_token: popular.wrapped_token(&bare_name),
        digit_suffix: bare_name.chars().last().is_some_and(|c| c.is_ascii_digit()),
        keyboard_typo,
        char_ngram_score: 0.0,
        normalized,
        bare: bare_name,
    }
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

/// A float32 vector: a base64 string of little-endian floats (the exported form), a
/// `{"shape": [n], "data": ...}` tensor, or a plain JSON array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum F32Vec {
    Str(String),
    List(Vec<f64>),
    B64 { data: String },
}

impl F32Vec {
    fn decode(&self, what: &str) -> Result<Vec<f64>, ModelError> {
        match self {
            F32Vec::List(v) => Ok(v.clone()),
            F32Vec::Str(data) | F32Vec::B64 { data } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data.trim())
                    .map_err(|e| ModelError::invalid(WHAT, format!("{what}: bad base64: {e}")))?;
                if bytes.len() % 4 != 0 {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("{what}: length is not a multiple of 4"),
                    ));
                }
                Ok(bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| f32::from_le_bytes(*c) as f64)
                    .collect())
            }
        }
    }
}

const WHAT: &str = "name_model";

#[derive(Debug, Clone, Deserialize)]
struct RawEcosystem {
    popular: String,
    mean: Vec<f64>,
    std: Vec<f64>,
    numeric_weights: Vec<f64>,
    ngram_weights: F32Vec,
    bias: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct RawNameModel {
    #[serde(default)]
    format: Option<String>,
    numeric_features: Vec<String>,
    max_distance: u32,
    ngram_min: usize,
    ngram_max: usize,
    n_buckets: u32,
    #[serde(default)]
    hash: Option<String>,
    ecosystems: BTreeMap<String, RawEcosystem>,
}

/// Weights and popular list for one ecosystem.
#[derive(Debug, Clone)]
pub struct EcosystemModel {
    pub popular: PopularIndex,
    mean: Vec<f64>,
    std: Vec<f64>,
    weights: Vec<f64>,
    ngram_weights: Vec<f64>,
    bias: f64,
}

/// Logistic regression over name features and hashed character n-grams.
#[derive(Debug, Clone)]
pub struct NameModel {
    numeric_features: Vec<String>,
    max_distance: u32,
    ngram_min: usize,
    ngram_max: usize,
    n_buckets: u32,
    pypi: Option<EcosystemModel>,
    npm: Option<EcosystemModel>,
}

/// Output of the name model for one name.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NameScore {
    pub logit: f64,
    pub prob: f64,
    pub features: NameFeatures,
    pub explanation: Option<String>,
    /// `(feature, value, logit contribution)`, largest first. The n-gram part appears as
    /// `char_ngram_score`.
    pub contributions: Vec<(String, f64, f64)>,
}

impl NameModel {
    /// Parse `name_model.json`; `read` loads the popular lists it names (paths relative to
    /// the model directory).
    pub fn from_json(
        text: &str,
        read: impl Fn(&str) -> Result<String, ModelError>,
    ) -> Result<Self, ModelError> {
        let raw: RawNameModel =
            serde_json::from_str(text).map_err(|e| ModelError::parse(WHAT, e))?;
        if let Some(f) = &raw.format {
            if f != "customs-name-lr-v1" {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("unsupported format '{f}'"),
                ));
            }
        }
        if let Some(h) = &raw.hash {
            if h != "fnv1a32" {
                return Err(ModelError::invalid(WHAT, format!("unsupported hash '{h}'")));
            }
        }
        for f in &raw.numeric_features {
            if !NUMERIC_NAME_FEATURES.contains(&f.as_str()) {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("unknown numeric feature '{f}'"),
                ));
            }
        }
        if raw.n_buckets == 0 || raw.n_buckets > (1 << 24) {
            return Err(ModelError::invalid(WHAT, "n_buckets must be in 1..=2^24"));
        }
        if raw.ngram_min == 0 || raw.ngram_min > raw.ngram_max {
            return Err(ModelError::invalid(
                WHAT,
                "need 1 <= ngram_min <= ngram_max",
            ));
        }
        let nf = raw.numeric_features.len();
        let mut model = NameModel {
            numeric_features: raw.numeric_features,
            max_distance: raw.max_distance,
            ngram_min: raw.ngram_min,
            ngram_max: raw.ngram_max,
            n_buckets: raw.n_buckets,
            pypi: None,
            npm: None,
        };
        for (key, e) in raw.ecosystems {
            let eco = match key.as_str() {
                "pypi" => Ecosystem::Pypi,
                "npm" => Ecosystem::Npm,
                other => {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("unknown ecosystem '{other}'"),
                    ))
                }
            };
            let at = |m: &str| format!("ecosystems.{key}.{m}");
            for (v, n) in [
                (&e.mean, "mean"),
                (&e.std, "std"),
                (&e.numeric_weights, "numeric_weights"),
            ] {
                if v.len() != nf {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("{} has {} values, expected {nf}", at(n), v.len()),
                    ));
                }
            }
            let ngram_weights = e.ngram_weights.decode(&at("ngram_weights"))?;
            if ngram_weights.len() != model.n_buckets as usize {
                return Err(ModelError::invalid(
                    WHAT,
                    format!(
                        "{} has {} values, n_buckets is {}",
                        at("ngram_weights"),
                        ngram_weights.len(),
                        model.n_buckets
                    ),
                ));
            }
            let popular = PopularIndex::from_text(eco, &read(&e.popular)?);
            let em = EcosystemModel {
                popular,
                mean: e.mean,
                // A constant feature has std 0 in training data; dividing by 1 keeps it inert.
                std: e
                    .std
                    .into_iter()
                    .map(|s| if s == 0.0 || !s.is_finite() { 1.0 } else { s })
                    .collect(),
                weights: e.numeric_weights,
                ngram_weights,
                bias: e.bias,
            };
            match eco {
                Ecosystem::Pypi => model.pypi = Some(em),
                Ecosystem::Npm => model.npm = Some(em),
            }
        }
        Ok(model)
    }

    pub fn ecosystem(&self, eco: Ecosystem) -> Option<&EcosystemModel> {
        match eco {
            Ecosystem::Pypi => self.pypi.as_ref(),
            Ecosystem::Npm => self.npm.as_ref(),
        }
    }

    pub fn n_buckets(&self) -> u32 {
        self.n_buckets
    }

    pub fn max_distance(&self) -> u32 {
        self.max_distance
    }

    /// Sum of n-gram weights over the distinct buckets of a normalized name.
    pub fn ngram_logit(&self, eco: Ecosystem, normalized: &str) -> f64 {
        let Some(em) = self.ecosystem(eco) else {
            return 0.0;
        };
        distinct_buckets(normalized, self.ngram_min, self.ngram_max, self.n_buckets)
            .into_iter()
            .map(|b| em.ngram_weights[b as usize])
            .sum()
    }

    /// Score a name; `None` when the model has no weights for the ecosystem.
    pub fn score(&self, eco: Ecosystem, name: &str) -> Option<NameScore> {
        let em = self.ecosystem(eco)?;
        let mut scratch = Scratch::default();
        let mut features =
            compute_features(eco, name, &em.popular, self.max_distance, &mut scratch);
        features.char_ngram_score = self.ngram_logit(eco, &features.normalized);
        let mut logit = em.bias + features.char_ngram_score;
        let mut contributions = Vec::with_capacity(self.numeric_features.len() + 1);
        for (i, f) in self.numeric_features.iter().enumerate() {
            let x = features.get(f).unwrap_or(0.0);
            let c = (x - em.mean[i]) / em.std[i] * em.weights[i];
            logit += c;
            contributions.push((f.clone(), x, c));
        }
        contributions.push((
            "char_ngram_score".to_string(),
            features.char_ngram_score,
            features.char_ngram_score,
        ));
        contributions.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        let explanation = features.explanation();
        Some(NameScore {
            logit,
            prob: sigmoid(logit),
            features,
            explanation,
            contributions,
        })
    }
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
        assert_eq!(
            normalize(Ecosystem::Pypi, "Foo__Bar.baz-_qux"),
            "foo-bar-baz-qux"
        );
        assert_eq!(normalize(Ecosystem::Pypi, "  Django "), "django");
        assert_eq!(normalize(Ecosystem::Npm, "@Babel/Core"), "@babel/core");
        assert_eq!(normalize(Ecosystem::Npm, "lodash.merge"), "lodash.merge");
        assert_eq!(bare("@babel/core"), "core");
        assert_eq!(bare("left-pad"), "left-pad");
    }

    #[test]
    fn fnv_known_values() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        assert_eq!(fnv1a32(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn ngrams_include_boundaries() {
        assert_eq!(ngram_buckets("ab", 1, 2, 1 << 20).len(), 7);
        let b = ngram_buckets("ab", 1, 1, 1 << 30);
        assert_eq!(b[0], fnv1a32(b"^") % (1 << 30));
        assert_eq!(ngram_buckets("a", 1, 9, 16).len(), 3 + 2 + 1);
        // "aaaa": the unigram "a" occurs four times but counts once.
        let d = distinct_buckets("aaaa", 1, 1, 1 << 30);
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn osa_distance_cases() {
        assert_eq!(osa_distance("requests", "requests"), 0);
        assert_eq!(osa_distance("reqeusts", "requests"), 1);
        assert_eq!(osa_distance("requets", "requests"), 1);
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
        assert!(keyboard_adjacent('n', 'm'));
        assert!(!keyboard_adjacent('q', 'p'));
        assert!(keyboard_adjacent('2', 'q'));
    }

    #[test]
    fn features_for_typosquats() {
        let p = pypi();
        let mut s = Scratch::default();
        let f = compute_features(Ecosystem::Pypi, "reqeusts", &p, 4, &mut s);
        assert_eq!(f.distance, 1);
        assert_eq!(f.nearest_popular.as_deref(), Some("requests"));
        assert_eq!(
            f.explanation().unwrap(),
            "1 edit from popular package 'requests'"
        );
        let f = compute_features(Ecosystem::Pypi, "requezts", &p, 4, &mut s);
        assert!(f.keyboard_typo);
        let f = compute_features(Ecosystem::Pypi, "Requests", &p, 4, &mut s);
        assert!(f.is_popular);
        assert_eq!(f.explanation(), None);
        let f = compute_features(Ecosystem::Pypi, "requests_auth_helper", &p, 4, &mut s);
        assert_eq!(f.contains_popular_token.as_deref(), Some("requests"));
        assert_eq!(f.n_hyphens, 2);
        assert_eq!(
            f.explanation().unwrap(),
            "wraps popular name 'requests' in extra words"
        );
        // "six" is too short to count as a wrapped token.
        let f = compute_features(Ecosystem::Pypi, "six-helpers", &p, 4, &mut s);
        assert_eq!(f.contains_popular_token, None);
        let f = compute_features(Ecosystem::Pypi, "zzzzzzzzzzzzzzzzz", &p, 4, &mut s);
        assert_eq!((f.distance, f.nearest_popular.as_deref()), (5, None));
        let f = compute_features(Ecosystem::Pypi, "urllib4", &p, 4, &mut s);
        assert!(f.digit_suffix);
        assert_eq!(f.n_digits, 1);
    }

    #[test]
    fn npm_bare_names() {
        let p = PopularIndex::new(
            Ecosystem::Npm,
            ["react", "@babel/core", "@types/node", "lodash"],
        );
        let mut s = Scratch::default();
        let f = compute_features(Ecosystem::Npm, "@evil/nodee", &p, 4, &mut s);
        assert!(f.has_scope);
        assert_eq!(f.len, 5);
        assert_eq!(
            (f.distance, f.nearest_popular.as_deref()),
            (1, Some("@types/node"))
        );
        // Same bare name as a popular package: distance 0 is ignored.
        let f = compute_features(Ecosystem::Npm, "@acme/core", &p, 4, &mut s);
        assert!(f.distance > 1);
    }

    #[test]
    fn ties_prefer_popular() {
        let p = PopularIndex::new(Ecosystem::Pypi, ["abcd", "abce"]);
        let mut s = Scratch::default();
        assert_eq!(p.nearest("abcf", 4, &mut s), (1, Some("abcd")));
    }

    #[test]
    fn nearest_matches_brute_force() {
        let names: Vec<String> = (0..400)
            .map(|i| {
                format!(
                    "pkg{}{}",
                    i * 7919 % 1000,
                    ["a", "bb", "ccc", "dddd"][i % 4]
                )
            })
            .collect();
        let p = PopularIndex::new(Ecosystem::Pypi, names.iter().map(|s| s.as_str()));
        let mut s = Scratch::default();
        for q in [
            "pkg123a",
            "pkg12bb",
            "pkgx",
            "pkg999dddd",
            "zzz",
            "pkg7919a",
        ] {
            let got = p.nearest(q, 4, &mut s);
            let mut best: Option<(u32, usize)> = None;
            for (r, n) in names.iter().enumerate() {
                let d = osa_distance(q, n);
                if d == 0 || d > 4 {
                    continue;
                }
                if best.is_none_or(|b| (d, r) < b) {
                    best = Some((d, r));
                }
            }
            let expect = best
                .map(|(d, r)| (d, Some(names[r].as_str())))
                .unwrap_or((5, None));
            assert_eq!(got, expect, "{q}");
        }
    }
}
