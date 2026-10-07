#!/usr/bin/env python3
"""Write the UNTRAINED development model set in models/dev/.

These artifacts are hand-written placeholders so `customs serve` runs end to end before the
training pipeline has produced real models. They use the exact formats of DESIGN.md
section 5, but the weights encode a few obvious rules of thumb, not anything learned from
data. The manifest says `"untrained": true` and `/api/model` reports it.

Real models are written to `models/` (not `models/dev/`) by python/customs_ml; the server
prefers `models/manifest.json` when it exists.

Usage: python3 models/dev/gen_dev_models.py
"""

import base64
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))

POPULAR_PYPI = """
boto3 urllib3 botocore requests setuptools certifi idna charset-normalizer typing-extensions
python-dateutil s3transfer packaging aiobotocore six numpy pyyaml grpcio-status cryptography
pip fsspec s3fs pydantic cffi attrs pycparser protobuf pandas importlib-metadata markupsafe
jinja2 pyasn1 rsa zipp platformdirs click wheel jmespath pytz filelock pydantic-core
annotated-types pluggy colorama virtualenv tomli pyjwt pytest wrapt iniconfig cachetools
google-api-core aiohttp yarl multidict frozenlist aiosignal async-timeout sqlalchemy greenlet
psutil pyarrow tzdata requests-oauthlib oauthlib googleapis-common-protos grpcio google-auth
docutils pygments rich markdown-it-py mdurl tqdm scipy pillow werkzeug flask itsdangerous
blinker openpyxl et-xmlfile decorator exceptiongroup soupsieve beautifulsoup4 lxml httpx
httpcore h11 anyio sniffio starlette fastapi uvicorn gunicorn django djangorestframework
celery kombu redis pymysql psycopg2 psycopg2-binary pymongo paramiko bcrypt pynacl matplotlib
kiwisolver cycler fonttools pyparsing contourpy scikit-learn joblib threadpoolctl networkx
sympy mpmath torch torchvision tensorflow keras tensorboard transformers tokenizers
huggingface-hub safetensors regex openai anthropic tiktoken langchain langchain-core numba
llvmlite pytest-cov coverage mock tox nox black isort flake8 pyflakes pycodestyle mypy
mypy-extensions ruff pylint astroid mccabe pre-commit identify nodeenv cfgv distlib sphinx
alabaster babel snowballstemmer imagesize jsonschema jsonschema-specifications referencing
rpds-py pyrsistent tabulate termcolor toml tomlkit poetry poetry-core pipenv build twine
keyring more-itertools simplejson ujson orjson msgpack dill cloudpickle python-dotenv
pyopenssl websocket-client websockets selenium playwright scrapy twisted zope-interface
setuptools-scm pexpect ptyprocess ipython traitlets jedi parso prompt-toolkit wcwidth
ipykernel jupyter-client jupyter-core notebook nbformat nbconvert tornado pyzmq debugpy
matplotlib-inline seaborn plotly statsmodels patsy xgboost lightgbm opencv-python imageio
scikit-image h5py tables sqlparse alembic mako marshmallow pyodbc azure-core
azure-storage-blob google-cloud-storage google-cloud-core awscli docker kubernetes ansible
fabric invoke pyserial pywin32 arrow pendulum humanize loguru structlog sentry-sdk
prometheus-client opentelemetry-api grpcio-tools thrift avro fastavro polars duckdb dask
distributed ray
""".split()

POPULAR_NPM = """
lodash react react-dom chalk tslib axios commander debug express semver uuid @types/node
@types/react @types/react-dom typescript moment fs-extra glob minimist yargs inquirer ws dotenv
body-parser cors mkdirp rimraf async bluebird underscore request colors classnames prop-types
vue @vue/compiler-sfc @angular/core @angular/common @angular/router rxjs zone.js webpack
webpack-cli webpack-dev-server babel-loader @babel/core @babel/parser @babel/traverse
@babel/types @babel/generator @babel/preset-env @babel/preset-react @babel/runtime eslint
eslint-plugin-react eslint-plugin-import @typescript-eslint/parser
@typescript-eslint/eslint-plugin prettier jest mocha chai sinon karma jasmine vitest
@testing-library/react @testing-library/jest-dom next nuxt svelte vite rollup esbuild parcel
postcss autoprefixer tailwindcss sass less styled-components @emotion/react @emotion/styled
@mui/material antd bootstrap jquery d3 three chart.js socket.io socket.io-client mongoose
mongodb mysql mysql2 pg redis ioredis sequelize typeorm prisma @prisma/client knex graphql
apollo-server @apollo/client jsonwebtoken bcrypt bcryptjs passport helmet morgan cookie-parser
express-session multer nodemailer node-fetch cross-fetch got superagent cheerio puppeteer
playwright @playwright/test cross-env nodemon concurrently npm-run-all husky lint-staged
ts-node tsx @swc/core core-js regenerator-runtime immer redux react-redux @reduxjs/toolkit mobx
zustand react-router react-router-dom react-query @tanstack/react-query formik yup zod joi ajv
date-fns dayjs luxon lodash.merge lodash.debounce lodash.get qs querystring path-to-regexp mime
mime-types form-data combined-stream follow-redirects http-proxy http-proxy-middleware
source-map source-map-support picocolors kleur ora cli-spinners listr execa cross-spawn which
shelljs chokidar graceful-fs js-yaml yaml ini dotenv-expand config winston pino bunyan log4js
uglify-js terser clean-css html-webpack-plugin css-loader style-loader file-loader url-loader
ts-loader eslint-config-prettier eslint-plugin-prettier event-stream left-pad is-number
kind-of isarray safe-buffer inherits readable-stream string_decoder once wrappy
balanced-match brace-expansion minimatch ms supports-color has-flag ansi-styles ansi-regex
strip-ansi string-width wrap-ansi color-convert color-name escape-string-regexp electron
react-native expo firebase aws-sdk @aws-sdk/client-s3 stripe openai @anthropic-ai/sdk
""".split()

UNTRAINED = (
    "UNTRAINED development placeholder. Hand-written rules of thumb in the production "
    "artifact formats so the binary runs end to end; replace with models/ from the "
    "training pipeline."
)


def b64(shape, values):
    data = b"".join(struct.pack("<f", v) for v in values)
    return {"shape": shape, "data": base64.b64encode(data).decode("ascii")}


def stump(feature_index, threshold, low, high, extra=None):
    """A depth-1 tree, or depth 2 when `extra` = (feature, threshold, low, high) refines the
    high branch. Missing values go left (the benign side)."""
    if extra is None:
        return {"nodes": [
            {"split": feature_index, "threshold": threshold, "left": 1, "right": 2,
             "default_left": True, "value": (low + high) / 2},
            {"leaf": low}, {"leaf": high}]}
    f2, t2, l2, h2 = extra
    return {"nodes": [
        {"split": feature_index, "threshold": threshold, "left": 1, "right": 2,
         "default_left": True, "value": (low + (l2 + h2) / 2) / 2},
        {"leaf": low},
        {"split": f2, "threshold": t2, "left": 3, "right": 4, "default_left": True,
         "value": (l2 + h2) / 2},
        {"leaf": l2}, {"leaf": h2}]}


def dump(name, obj):
    with open(os.path.join(HERE, name), "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")


def main():
    feats = ["inst_download_exec", "inst_exfil_endpoint", "inst_proc_exec", "inst_network",
             "inst_decode_obf", "inst_dyn_code", "inst_secret_paths", "inst_env_access",
             "inst_persistence", "inst_obf_ident_ratio", "inst_ip_url"]
    fi = {f: i for i, f in enumerate(feats)}
    trees = [
        stump(fi["inst_download_exec"], 0.5, 0.0, 4.0),
        stump(fi["inst_exfil_endpoint"], 0.5, 0.0, 3.5),
        stump(fi["inst_proc_exec"], 0.5, 0.0, 1.0, (fi["inst_network"], 0.5, 1.0, 2.5)),
        stump(fi["inst_decode_obf"], 0.5, 0.0, 0.8, (fi["inst_dyn_code"], 0.5, 0.8, 2.5)),
        stump(fi["inst_secret_paths"], 0.5, 0.0, 2.0),
        stump(fi["inst_env_access"], 0.5, 0.0, 0.3, (fi["inst_network"], 0.5, 0.3, 1.5)),
        stump(fi["inst_persistence"], 0.5, 0.0, 2.0),
        stump(fi["inst_obf_ident_ratio"], 0.2, 0.0, 1.5),
        stump(fi["inst_ip_url"], 0.5, 0.0, 1.0),
    ]
    dump("code_gbdt.json", {"feature_names": feats, "base_score": -3.0,
                            "objective": "binary", "trees": trees})

    numeric = ["len", "n_digits", "n_hyphens", "n_underscores", "n_dots", "has_scope",
               "is_popular", "dist1", "dist2", "dist3", "contains_popular_token", "digit_suffix"]
    weights = {"is_popular": -8.0, "dist1": 5.5, "dist2": 3.5, "dist3": 1.0,
               "contains_popular_token": 2.0, "digit_suffix": 0.5}
    eco = {
        "mean": [0.0] * len(numeric),
        "std": [1.0] * len(numeric),
        "numeric_weights": [weights.get(f, 0.0) for f in numeric],
        "ngram_weights": b64([16], [0.0] * 16)["data"],
        "bias": -4.0,
    }
    dump("name_model.json", {
        "format": "customs-name-lr-v1",
        "numeric_features": numeric,
        "max_distance": 4,
        "ngram_min": 1, "ngram_max": 4, "n_buckets": 16, "hash": "fnv1a32",
        "ecosystems": {
            "pypi": dict(eco, popular="popular_pypi.txt"),
            "npm": dict(eco, popular="popular_npm.txt"),
        },
    })

    # A constant network (zero weights, output bias -4) that only exercises the code path.
    dump("code_nn.json", {
        "format": "customs-code-cnn-v1",
        "vocab": {"<pad>": 0, "<unk>": 1}, "max_len": 64,
        "embedding": b64([2, 2], [0.0] * 4),
        "convs": [{"kernel": 1, "weight": b64([1, 2, 1], [0.0, 0.0]),
                   "bias": b64([1], [0.0])}],
        "dense": [{"weight": b64([1, 1], [0.0]), "bias": b64([1], [-4.0]),
                   "activation": "none"}],
    })

    dump("ensemble.json", {
        "format": "customs-ensemble-v1",
        "components": ["code_gbdt", "code_nn", "name"],
        "weights": {"code_gbdt": 1.0, "code_nn": 0.0, "name": 1.0},
        "bias": 2.0,
        "fallbacks": [
            {"missing": ["code_nn"], "weights": {"code_gbdt": 1.0, "name": 1.0}, "bias": 2.0},
            {"missing": ["name"], "weights": {"code_gbdt": 1.0, "code_nn": 0.0}, "bias": 0.0},
            {"missing": ["code_nn", "name"], "weights": {"code_gbdt": 1.0}, "bias": 0.0},
            {"missing": ["code_gbdt"], "weights": {"code_nn": 0.0, "name": 1.0}, "bias": 0.0},
            {"missing": ["code_gbdt", "code_nn"], "weights": {"name": 1.0}, "bias": 0.0},
        ],
        "thresholds": {"warn": 0.5, "block": 0.9, "target_fpr_warn": 0.01,
                       "target_fpr_block": 0.001},
    })

    for name, lst in (("popular_pypi.txt", POPULAR_PYPI), ("popular_npm.txt", POPULAR_NPM)):
        with open(os.path.join(HERE, name), "w") as f:
            f.write("\n".join(lst) + "\n")

    dump("manifest.json", {
        "model_version": "dev-untrained",
        "feature_schema_version": 1,
        "code_gbdt": "code_gbdt.json",
        "name_model": "name_model.json",
        "code_nn": "code_nn.json",
        "ensemble": "ensemble.json",
        "popular_names": {"pypi": "popular_pypi.txt", "npm": "popular_npm.txt"},
        "untrained": True,
        "description": UNTRAINED,
    })
    print("wrote untrained dev models to", HERE)


if __name__ == "__main__":
    main()
