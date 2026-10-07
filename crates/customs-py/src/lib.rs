//! Python bindings for customs-scan (PyO3). Built with maturin; the module is
//! `customs_scan`.
//!
//! Reports are returned as plain dicts with exactly the JSON shape of DESIGN.md section 4,
//! so Python code can treat CLI output and binding output interchangeably.

use ::customs_scan as scan;
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

fn parse_ecosystem(eco: Option<&str>) -> PyResult<Option<scan::Ecosystem>> {
    eco.map(|s| s.parse().map_err(PyValueError::new_err))
        .transpose()
}

fn to_py(py: Python<'_>, v: &Value) -> PyResult<Py<PyAny>> {
    Ok(match v {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any().unbind()
            } else {
                n.as_f64()
                    .unwrap_or(f64::NAN)
                    .into_pyobject(py)?
                    .into_any()
                    .unbind()
            }
        }
        Value::String(s) => s.into_pyobject(py)?.into_any().unbind(),
        Value::Array(a) => {
            let list = PyList::empty(py);
            for item in a {
                list.append(to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        Value::Object(o) => {
            let d = PyDict::new(py);
            for (k, item) in o {
                d.set_item(k, to_py(py, item)?)?;
            }
            d.into_any().unbind()
        }
    })
}

fn report_to_py(
    py: Python<'_>,
    result: Result<scan::ScanReport, scan::ScanError>,
) -> PyResult<Py<PyAny>> {
    let report = result.map_err(|e| match e {
        scan::ScanError::Io(io) => PyIOError::new_err(io.to_string()),
        other => PyValueError::new_err(other.to_string()),
    })?;
    // Feature values serialize as JSON floats (serde keeps f64 as float even when integral),
    // so they arrive in Python as floats and downstream frames get a uniform dtype.
    let v = serde_json::to_value(&report).map_err(|e| PyValueError::new_err(e.to_string()))?;
    to_py(py, &v)
}

fn options(tokens: bool) -> scan::ScanOptions {
    scan::ScanOptions {
        tokens,
        ..Default::default()
    }
}

/// Scan an archive file on disk and return the report as a dict.
#[pyfunction]
#[pyo3(signature = (path, tokens = false, ecosystem = None))]
fn scan_file(
    py: Python<'_>,
    path: std::path::PathBuf,
    tokens: bool,
    ecosystem: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let eco = parse_ecosystem(ecosystem)?;
    let opts = options(tokens);
    let result = py.detach(|| scan::scan_path(&path, eco, &opts));
    report_to_py(py, result)
}

/// Scan archive bytes held in memory and return the report as a dict.
#[pyfunction]
#[pyo3(signature = (data, filename, tokens = false, ecosystem = None))]
fn scan_bytes(
    py: Python<'_>,
    data: Vec<u8>,
    filename: &str,
    tokens: bool,
    ecosystem: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let eco = parse_ecosystem(ecosystem)?;
    let opts = options(tokens);
    let filename = filename.to_string();
    let result = py.detach(|| scan::scan_archive(&data, &filename, eco, &opts));
    report_to_py(py, result)
}

/// The ordered feature name list of the current schema.
#[pyfunction]
fn feature_names() -> Vec<&'static str> {
    scan::feature_names()
}

#[pymodule]
fn customs_scan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(scan_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(feature_names, m)?)?;
    m.add("FEATURE_SCHEMA_VERSION", scan::FEATURE_SCHEMA_VERSION)?;
    m.add("INDICATORS", scan::INDICATOR_NAMES.to_vec())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
