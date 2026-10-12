# models/dev: UNTRAINED placeholders

Nothing in this directory was trained on data. These files use the production artifact
formats (DESIGN.md section 5) with hand-written weights so `customs serve` can run end to
end before the training pipeline has produced real models:

- `code_gbdt.json`: nine stumps on obvious install-time indicators (download-and-execute,
  exfiltration endpoints, shell plus network, decode plus eval, credential paths).
- `name_model.json`: one or two edits from a popular name, popular-name wrapping, a trailing
  digit. No n-gram weights.
- `code_nn.json`: a constant network (all weights zero) that only exercises the code path.
- `ensemble.json`: equal stacking of the tree and name logits; the code CNN has weight zero.
- `popular_*.txt`: short hand-written lists (about 250 names each), not a download ranking.

The manifest sets `"untrained": true` and `model_version` `dev-untrained`, and `/api/model`
reports both. `customs` loads `models/manifest.json` when it exists and falls back to
`models/dev/manifest.json` otherwise. Regenerate with `python3 models/dev/gen_dev_models.py`.
