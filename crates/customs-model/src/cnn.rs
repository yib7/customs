//! Forward pass of the code CNN (DESIGN.md section 5, `code_nn.json`, format
//! `customs-code-cnn-v1`).
//!
//! Architecture: token embedding, one 1D convolution per kernel size (valid padding),
//! ReLU, global max pool over positions, concatenation, dense layers each with its own
//! activation (`relu` or `none`), and a single output logit. Weights use PyTorch layouts (`Conv1d.weight` is
//! `[out_channels, in_channels, kernel]`, `Linear.weight` is `[out, in]`) so the exporter
//! can dump tensors without reshaping.

use std::collections::HashMap;

use base64::Engine as _;
use serde::Deserialize;

use crate::{sigmoid, ModelError};

const WHAT: &str = "code_nn";
pub const PAD_ID: u32 = 0;
pub const UNK_ID: u32 = 1;
/// Short inputs are right-padded to at least this many positions.
pub const MIN_LEN: usize = 16;

/// A float32 tensor as stored on disk: little-endian bytes, base64-encoded.
#[derive(Debug, Clone, Deserialize)]
pub struct TensorSpec {
    pub shape: Vec<usize>,
    pub data: String,
}

impl TensorSpec {
    pub fn decode(&self, what: &str) -> Result<Vec<f32>, ModelError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.data.trim())
            .map_err(|e| ModelError::invalid(WHAT, format!("{what}: bad base64: {e}")))?;
        let expected: usize = self.shape.iter().product();
        if bytes.len() != expected * 4 {
            return Err(ModelError::invalid(
                WHAT,
                format!(
                    "{what}: shape {:?} needs {} bytes, data has {}",
                    self.shape,
                    expected * 4,
                    bytes.len()
                ),
            ));
        }
        let v: Vec<f32> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes(*c))
            .collect();
        if v.iter().any(|x| !x.is_finite()) {
            return Err(ModelError::invalid(
                WHAT,
                format!("{what}: non-finite weight"),
            ));
        }
        Ok(v)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawConv {
    #[serde(alias = "kernel_size")]
    kernel: usize,
    weight: TensorSpec,
    bias: TensorSpec,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDense {
    weight: TensorSpec,
    bias: TensorSpec,
    /// `relu` or `none`; when absent, ReLU between layers and none after the last.
    #[serde(default)]
    activation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawCnn {
    #[serde(default)]
    format: Option<String>,
    vocab: HashMap<String, u32>,
    max_len: usize,
    embedding: TensorSpec,
    convs: Vec<RawConv>,
    dense: Vec<RawDense>,
}

#[derive(Debug, Clone)]
struct Conv {
    k: usize,
    out: usize,
    /// Re-laid out as `[out][k][dim]` so the inner loop reads both operands contiguously.
    weight: Vec<f32>,
    bias: Vec<f32>,
}

#[derive(Debug, Clone)]
struct Dense {
    input: usize,
    out: usize,
    weight: Vec<f32>,
    bias: Vec<f32>,
    relu: bool,
}

/// A loaded code CNN.
#[derive(Debug, Clone)]
pub struct CodeCnn {
    vocab: HashMap<String, u32>,
    max_len: usize,
    vocab_rows: usize,
    dim: usize,
    embedding: Vec<f32>,
    convs: Vec<Conv>,
    dense: Vec<Dense>,
}

impl CodeCnn {
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        let raw: RawCnn = serde_json::from_str(text).map_err(|e| ModelError::parse(WHAT, e))?;
        if let Some(f) = &raw.format {
            if f != "customs-code-cnn-v1" {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("unsupported format '{f}'"),
                ));
            }
        }
        if raw.embedding.shape.len() != 2 {
            return Err(ModelError::invalid(WHAT, "embedding must be [vocab, dim]"));
        }
        let (vocab_rows, dim) = (raw.embedding.shape[0], raw.embedding.shape[1]);
        let embedding = raw.embedding.decode("embedding")?;
        if vocab_rows < 2 || dim == 0 {
            return Err(ModelError::invalid(
                WHAT,
                "embedding needs at least <pad> and <unk>",
            ));
        }
        if let Some((tok, id)) = raw.vocab.iter().find(|(_, id)| **id as usize >= vocab_rows) {
            return Err(ModelError::invalid(
                WHAT,
                format!("vocab token '{tok}' has id {id} beyond embedding rows {vocab_rows}"),
            ));
        }
        if raw.max_len == 0 {
            return Err(ModelError::invalid(WHAT, "max_len must be positive"));
        }
        if raw.convs.is_empty() {
            return Err(ModelError::invalid(
                WHAT,
                "at least one conv layer is required",
            ));
        }
        let mut convs = Vec::with_capacity(raw.convs.len());
        for (i, c) in raw.convs.iter().enumerate() {
            let at = format!("convs[{i}]");
            let w = c.weight.decode(&format!("{at}.weight"))?;
            let b = c.bias.decode(&format!("{at}.bias"))?;
            let [out, ind, k] = c.weight.shape[..] else {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("{at}.weight must be 3-D"),
                ));
            };
            if ind != dim || k != c.kernel || k == 0 || b.len() != out {
                return Err(ModelError::invalid(
                    WHAT,
                    format!(
                        "{at}: weight {:?} does not fit dim {dim} / kernel {}",
                        c.weight.shape, c.kernel
                    ),
                ));
            }
            let mut weight = vec![0.0f32; out * k * dim];
            for o in 0..out {
                for d in 0..dim {
                    for j in 0..k {
                        weight[(o * k + j) * dim + d] = w[(o * dim + d) * k + j];
                    }
                }
            }
            convs.push(Conv {
                k,
                out,
                weight,
                bias: b,
            });
        }
        let mut input = convs.iter().map(|c| c.out).sum::<usize>();
        let mut dense = Vec::with_capacity(raw.dense.len());
        for (i, d) in raw.dense.iter().enumerate() {
            let at = format!("dense[{i}]");
            let w = d.weight.decode(&format!("{at}.weight"))?;
            let b = d.bias.decode(&format!("{at}.bias"))?;
            let [out, ind] = d.weight.shape[..] else {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("{at}.weight must be 2-D"),
                ));
            };
            if ind != input || b.len() != out {
                return Err(ModelError::invalid(
                    WHAT,
                    format!(
                        "{at}: weight {:?} does not take {input} inputs",
                        d.weight.shape
                    ),
                ));
            }
            let relu = match d.activation.as_deref() {
                Some("relu") => true,
                Some("none") | Some("linear") => false,
                None => i + 1 < raw.dense.len(),
                Some(other) => {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("{at}: unsupported activation '{other}'"),
                    ))
                }
            };
            dense.push(Dense {
                input,
                out,
                weight: w,
                bias: b,
                relu,
            });
            input = out;
        }
        if input != 1 {
            return Err(ModelError::invalid(
                WHAT,
                "the last layer must have one output",
            ));
        }
        Ok(Self {
            vocab: raw.vocab,
            max_len: raw.max_len,
            vocab_rows,
            dim,
            embedding,
            convs,
            dense,
        })
    }

    pub fn max_len(&self) -> usize {
        self.max_len
    }

    pub fn vocab_size(&self) -> usize {
        self.vocab_rows
    }

    /// Token ids after truncation and padding, exactly as the model sees them.
    pub fn encode<S: AsRef<str>>(&self, tokens: &[S]) -> Vec<u32> {
        let max_k = self.convs.iter().map(|c| c.k).max().unwrap_or(1);
        let mut ids: Vec<u32> = tokens
            .iter()
            .take(self.max_len)
            .map(|t| self.vocab.get(t.as_ref()).copied().unwrap_or(UNK_ID))
            .collect();
        let target = MIN_LEN.max(max_k);
        if ids.len() < target {
            ids.resize(target, PAD_ID);
        }
        ids
    }

    /// Output logit for a token stream.
    pub fn logit<S: AsRef<str>>(&self, tokens: &[S]) -> f32 {
        self.logit_ids(&self.encode(tokens))
    }

    pub fn prob<S: AsRef<str>>(&self, tokens: &[S]) -> f64 {
        sigmoid(self.logit(tokens) as f64)
    }

    /// Forward pass over already-encoded ids (`ids.len()` at least the largest kernel).
    pub fn logit_ids(&self, ids: &[u32]) -> f32 {
        let dim = self.dim;
        let row = |id: u32| {
            let r = (id as usize).min(self.vocab_rows - 1) * dim;
            &self.embedding[r..r + dim]
        };
        let mut pooled: Vec<f32> = Vec::with_capacity(self.convs.iter().map(|c| c.out).sum());
        for conv in &self.convs {
            let positions = ids.len() + 1 - conv.k.min(ids.len() + 1);
            for o in 0..conv.out {
                let w = &conv.weight[o * conv.k * dim..(o + 1) * conv.k * dim];
                let mut best = f32::NEG_INFINITY;
                for t in 0..positions {
                    let mut acc = conv.bias[o];
                    for j in 0..conv.k {
                        acc += dot(&w[j * dim..(j + 1) * dim], row(ids[t + j]));
                    }
                    best = best.max(acc);
                }
                // ReLU commutes with max, so applying it once after pooling is exact.
                pooled.push(if positions == 0 { 0.0 } else { best.max(0.0) });
            }
        }
        let mut h = pooled;
        let mut next = Vec::new();
        for layer in &self.dense {
            next.clear();
            for o in 0..layer.out {
                let w = &layer.weight[o * layer.input..(o + 1) * layer.input];
                let mut v = layer.bias[o] + dot(w, &h);
                if layer.relu {
                    v = v.max(0.0);
                }
                next.push(v);
            }
            std::mem::swap(&mut h, &mut next);
        }
        h[0]
    }
}

#[inline]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    // Four independent accumulators let the compiler vectorize without -ffast-math.
    let mut acc = [0.0f32; 4];
    let chunks = a.len() / 4;
    for i in 0..chunks {
        for l in 0..4 {
            acc[l] += a[i * 4 + l] * b[i * 4 + l];
        }
    }
    let mut s = (acc[0] + acc[1]) + (acc[2] + acc[3]);
    for i in chunks * 4..a.len() {
        s += a[i] * b[i];
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(v: &[f32]) -> String {
        let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn tiny_network_by_hand() {
        // vocab 3, dim 1, one conv k=1 with weight 2 bias -1, dense 1x1 weight 3 bias 0.5.
        let json = format!(
            r#"{{"format": "customs-code-cnn-v1", "vocab": {{"<pad>": 0, "<unk>": 1, "x": 2}}, "max_len": 3,
               "embedding": {{"shape": [3, 1], "data": "{}"}},
               "convs": [{{"kernel": 1, "weight": {{"shape": [1, 1, 1], "data": "{}"}}, "bias": {{"shape": [1], "data": "{}"}}}}],
               "dense": [{{"weight": {{"shape": [1, 1], "data": "{}"}}, "bias": {{"shape": [1], "data": "{}"}}, "activation": "none"}}]}}"#,
            b64(&[0.0, 0.5, 4.0]),
            b64(&[2.0]),
            b64(&[-1.0]),
            b64(&[3.0]),
            b64(&[0.5])
        );
        let m = CodeCnn::from_json(&json).unwrap();
        // max over tokens of 2*e - 1: "x" gives 7, then dense 3*7 + 0.5.
        assert_eq!(m.logit(&["y", "x"]), 21.5);
        // Unknown token gives 2*0.5 - 1 = 0 and padding gives -1, so ReLU(max) = 0 -> 0.5.
        assert_eq!(m.logit(&["y"]), 0.5);
        // Truncated to max_len, then padded to the minimum length.
        let ids = m.encode(&["x", "x", "x", "x"]);
        assert_eq!(ids.len(), MIN_LEN);
        assert_eq!(&ids[..4], &[2, 2, 2, 0]);
    }

    #[test]
    fn dot_matches_naive() {
        let a: Vec<f32> = (0..11).map(|i| i as f32 * 0.5).collect();
        let b: Vec<f32> = (0..11).map(|i| 1.0 - i as f32 * 0.25).collect();
        let naive: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        assert!((dot(&a, &b) - naive).abs() < 1e-4);
    }
}
