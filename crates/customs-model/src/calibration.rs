//! Probability calibration applied as a piecewise-linear map.
//!
//! The exporter writes knots (`x` ascending, `y` non-decreasing): the breakpoints of an
//! isotonic regression (`method: "isotonic"`, used for the tree model's own score), or a
//! dense sampling of a Platt curve (`method: "platt"`, used for the ensemble because it is
//! strictly increasing, so strict thresholds do not land on tied plateaus). Either way we
//! interpolate linearly between knots and clamp outside them, which is what `np.interp`
//! does on the Python side.

use serde::{Deserialize, Serialize};

use crate::ModelError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Calibration {
    #[serde(default = "default_method")]
    pub method: String,
    pub x: Vec<f64>,
    pub y: Vec<f64>,
}

fn default_method() -> String {
    "isotonic".to_string()
}

impl Calibration {
    /// Check the invariants the interpolation relies on.
    pub fn validate(&self, what: &str) -> Result<(), ModelError> {
        if self.method != "isotonic" && self.method != "platt" {
            return Err(ModelError::invalid(
                what,
                format!("unsupported calibration method '{}'", self.method),
            ));
        }
        if self.x.len() != self.y.len() {
            return Err(ModelError::invalid(
                what,
                format!(
                    "calibration x has {} points but y has {}",
                    self.x.len(),
                    self.y.len()
                ),
            ));
        }
        if self.x.is_empty() {
            return Err(ModelError::invalid(what, "calibration has no points"));
        }
        if self.x.windows(2).any(|w| w[1] < w[0]) {
            return Err(ModelError::invalid(what, "calibration x is not sorted"));
        }
        if self.x.iter().chain(self.y.iter()).any(|v| !v.is_finite()) {
            return Err(ModelError::invalid(
                what,
                "calibration contains a non-finite value",
            ));
        }
        if self.y.windows(2).any(|w| w[1] < w[0]) {
            return Err(ModelError::invalid(
                what,
                "calibration y is not non-decreasing",
            ));
        }
        if self.y.iter().any(|v| !(0.0..=1.0).contains(v)) {
            return Err(ModelError::invalid(what, "calibration y is outside [0, 1]"));
        }
        Ok(())
    }

    /// Map a raw probability to a calibrated one.
    pub fn apply(&self, p: f64) -> f64 {
        interp(p, &self.x, &self.y)
    }
}

/// `numpy.interp` semantics: clamp outside `[x0, xn]`, linear inside. With repeated `x`
/// values the right-most matching segment wins, as in numpy.
pub fn interp(v: f64, xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    if n == 0 {
        return v;
    }
    if v.is_nan() {
        return f64::NAN;
    }
    if v <= xs[0] {
        return ys[0];
    }
    if v >= xs[n - 1] {
        return ys[n - 1];
    }
    // First index with xs[i] > v; v lies in [xs[i-1], xs[i]).
    let i = xs.partition_point(|&x| x <= v);
    let (x0, x1, y0, y1) = (xs[i - 1], xs[i], ys[i - 1], ys[i]);
    if x1 == x0 {
        return y1;
    }
    y0 + (v - x0) * (y1 - y0) / (x1 - x0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_and_interpolates() {
        let c = Calibration {
            method: "isotonic".into(),
            x: vec![0.1, 0.5, 0.9],
            y: vec![0.0, 0.2, 1.0],
        };
        c.validate("t").unwrap();
        assert_eq!(c.apply(0.0), 0.0);
        assert_eq!(c.apply(1.0), 1.0);
        assert!((c.apply(0.3) - 0.1).abs() < 1e-12);
        assert!((c.apply(0.7) - 0.6).abs() < 1e-12);
        assert_eq!(c.apply(0.5), 0.2);
    }

    #[test]
    fn rejects_bad_shapes() {
        let c = Calibration {
            method: "isotonic".into(),
            x: vec![0.5, 0.1],
            y: vec![0.0, 1.0],
        };
        assert!(c.validate("t").is_err());
        let c = Calibration {
            method: "spline".into(),
            x: vec![0.1],
            y: vec![0.0],
        };
        assert!(c.validate("t").is_err());
        let c = Calibration {
            method: "platt".into(),
            x: vec![0.1, 0.9],
            y: vec![0.2, 0.8],
        };
        assert!(c.validate("t").is_ok());
        // y must be a non-decreasing probability.
        for y in [vec![0.5, 0.2], vec![0.0, 1.5], vec![-0.1, 0.5]] {
            let c = Calibration {
                method: "isotonic".into(),
                x: vec![0.1, 0.9],
                y,
            };
            assert!(c.validate("t").is_err(), "{:?}", c.y);
        }
    }
}
