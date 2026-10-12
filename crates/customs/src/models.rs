//! Where the trained models live on disk, and loading them at startup.
//!
//! `serve`, `scan`, and the in-process checker behind `check`, `audit`, the hook and the MCP
//! server all start by looking for a model directory: an explicit `--models`,
//! `CUSTOMS_MODELS`, the working directory's `models/` (for `serve` only), then paths
//! relative to the executable. Each candidate's `dev/` placeholders are the fallback, and
//! with nothing found the engine runs policy-only.

use std::path::{Path, PathBuf};

use customs_model::Models;

/// The directories [`find_models_dir`] tries, in order: an explicit path, else
/// `CUSTOMS_MODELS`, `<project_dir>/models` (only for `serve`; see
/// [`crate::config::resolve_policy`]), and paths relative to the executable.
fn model_roots(
    explicit: Option<&Path>,
    project_dir: Option<&Path>,
    env_models: Option<PathBuf>,
    exe: Option<&Path>,
) -> Vec<PathBuf> {
    if let Some(p) = explicit {
        return vec![p.to_path_buf()];
    }
    let mut roots: Vec<PathBuf> = env_models.into_iter().collect();
    roots.extend(project_dir.map(|d| d.join("models")));
    if let Some(dir) = exe.and_then(Path::parent) {
        // target/{debug,release}/customs in a checkout, or <prefix>/bin/customs.
        roots.push(dir.join("../../models"));
        roots.push(dir.join("../share/customs/models"));
    }
    roots
}

/// Find a model directory among [`model_roots`] (each, or its `dev/` subdirectory). Real
/// models in a directory win over its `dev/` placeholders.
pub fn find_models_dir(explicit: Option<&Path>, project_dir: Option<&Path>) -> Option<PathBuf> {
    first_models_dir(&default_model_roots(explicit, project_dir))
}

fn default_model_roots(explicit: Option<&Path>, project_dir: Option<&Path>) -> Vec<PathBuf> {
    let exe = std::env::current_exe().ok();
    let env_models = std::env::var_os("CUSTOMS_MODELS").map(PathBuf::from);
    model_roots(explicit, project_dir, env_models, exe.as_deref())
}

fn first_models_dir(roots: &[PathBuf]) -> Option<PathBuf> {
    roots
        .iter()
        .flat_map(|root| [root.clone(), root.join("dev")])
        .find(|dir| dir.join("manifest.json").is_file())
}

/// Load models from [`find_models_dir`]; with nothing found, run policy-only.
pub fn load_models(explicit: Option<&Path>, project_dir: Option<&Path>) -> anyhow::Result<Models> {
    match find_models_dir(explicit, project_dir) {
        Some(dir) => {
            let m = Models::load(&dir)
                .map_err(|e| anyhow::anyhow!("loading models from {}: {e}", dir.display()))?;
            if let Some(e) = &m.metrics_error {
                tracing::warn!(dir = %dir.display(), error = %e, "ignoring unreadable model metrics");
            }
            if m.manifest.untrained {
                tracing::warn!(
                    dir = %dir.display(),
                    version = m.model_version(),
                    "using UNTRAINED placeholder models: their scores mean nothing; point \
                     --models or CUSTOMS_MODELS at the trained models directory (models/ in the \
                     Customs repository)"
                );
            } else {
                tracing::info!(dir = %dir.display(), version = m.model_version(), "loaded models");
            }
            Ok(m)
        }
        None => {
            if let Some(p) = explicit {
                anyhow::bail!(
                    "no models in {}: no manifest.json there or in {}/dev; point --models or \
                     CUSTOMS_MODELS at the trained models directory (models/ in the Customs \
                     repository)",
                    p.display(),
                    p.display()
                );
            }
            let roots = default_model_roots(None, project_dir);
            tracing::error!("{}", no_models_message(&roots));
            Ok(Models::empty())
        }
    }
}

/// What to say when [`find_models_dir`] found nothing in `roots`.
fn no_models_message(roots: &[PathBuf]) -> String {
    let tried: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
    format!(
        "no models found in {} (or their dev/ subdirectories): the classifier is OFF and \
         verdicts use the policy rules only; pass --models DIR or set CUSTOMS_MODELS",
        if tried.is_empty() {
            "any directory".to_string()
        } else {
            tried.join(", ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_models_dir_without_project_dir_ignores_models() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("models")).unwrap();
        std::fs::write(project.path().join("models/manifest.json"), "{}").unwrap();
        let exe = Path::new("/opt/customs/bin/customs");
        let roots = model_roots(None, None, None, Some(exe));
        assert!(
            roots.iter().all(|r| !r.starts_with(project.path())),
            "{roots:?}"
        );
        assert_eq!(first_models_dir(&roots), None);
        // `serve` looks in its working directory, after CUSTOMS_MODELS.
        let roots = model_roots(None, Some(project.path()), None, Some(exe));
        assert_eq!(
            first_models_dir(&roots),
            Some(project.path().join("models"))
        );
        let env = PathBuf::from("/env/models");
        let roots = model_roots(None, Some(project.path()), Some(env.clone()), None);
        assert_eq!(roots[0], env);
        // An explicit directory is the only one tried.
        let roots = model_roots(Some(Path::new("/x")), Some(project.path()), Some(env), None);
        assert_eq!(roots, vec![PathBuf::from("/x")]);
    }

    #[test]
    fn no_models_message_lists_roots_and_remedy() {
        let m = no_models_message(&[PathBuf::from("/env/models"), PathBuf::from("/opt/models")]);
        assert!(m.contains("/env/models, /opt/models"), "{m}");
        assert!(m.contains("classifier is OFF"), "{m}");
        assert!(
            m.contains("--models DIR") && m.contains("CUSTOMS_MODELS"),
            "{m}"
        );
        assert!(!m.contains("  "), "{m}");
    }
}
