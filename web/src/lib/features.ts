// Human-readable labels for model features (DESIGN.md section 4) and evidence indicators.

const INDICATORS: Record<string, { label: string; short: string }> = {
  proc_exec: { label: 'Runs shell commands', short: 'Shell command' },
  dyn_code: { label: 'Executes dynamically built code', short: 'Dynamic code' },
  network: { label: 'Makes network requests', short: 'Network call' },
  decode_obf: { label: 'Decodes hidden data (base64, hex, zlib)', short: 'Decoding' },
  env_access: { label: 'Reads environment variables', short: 'Env access' },
  secret_paths: { label: 'References credential files (SSH keys, cloud tokens, browser data)', short: 'Credential path' },
  persistence: { label: 'Sets up persistence (shell profiles, cron, startup items)', short: 'Persistence' },
  recon: { label: 'Collects host and user information', short: 'Recon' },
  download_exec: { label: 'Downloads and runs a payload', short: 'Download and run' },
  exfil_endpoint: { label: 'Contacts a known exfiltration endpoint (webhooks, paste sites)', short: 'Exfil endpoint' },
  ip_url: { label: 'Contains a URL with a raw IP address', short: 'IP address URL' },
  url: { label: 'Contains URLs', short: 'URL' },
  file_write: { label: 'Writes files', short: 'File write' },
  crypto_wallet: { label: 'References cryptocurrency wallets', short: 'Crypto wallet' },
};

const FEATURES: Record<string, string> = {
  n_files: 'Number of files',
  total_bytes: 'Total package size',
  max_file_bytes: 'Largest file size',
  n_py: 'Number of Python files',
  n_js: 'Number of JavaScript files',
  n_shell: 'Shell or batch scripts included',
  n_binary: 'Native executables included',
  n_hidden: 'Hidden dotfiles included',
  n_minified_js: 'Minified JavaScript files',
  has_setup_py: 'Has a setup.py',
  has_pyproject: 'Has a pyproject.toml',
  has_package_json: 'Has a package.json',
  n_npm_install_scripts: 'npm install scripts',
  inst_n_lines: 'Amount of install-time code',
  inst_bytes: 'Size of install-time code',
  all_n_lines: 'Total lines of code',
  inst_max_line_len: 'Very long line in install-time code',
  all_max_line_len: 'Very long line in the package',
  inst_max_str_entropy: 'Random-looking strings in install-time code',
  all_max_str_entropy: 'Random-looking strings in the package',
  inst_mean_str_entropy: 'Average string randomness in install-time code',
  inst_longest_b64_run: 'Long base64 blob in install-time code',
  all_longest_b64_run: 'Long base64 blob in the package',
  inst_hex_escape_count: 'Hex-escaped strings in install-time code',
  all_hex_escape_count: 'Hex-escaped strings in the package',
  inst_obf_ident_ratio: 'Obfuscated identifiers in install-time code',
  inst_nonascii_ratio: 'Non-ASCII characters in install-time code',
  inst_long_line_ratio: 'Many very long lines in install-time code',
  meta_desc_len: 'Description length',
  meta_has_homepage: 'Has a homepage',
  meta_has_repo: 'Links a source repository',
  meta_has_author_email: 'Has an author email',
  meta_has_license: 'Declares a license',
  meta_n_deps: 'Number of dependencies',
  meta_readme_bytes: 'README size',
  meta_version_major: 'Major version number',
  meta_version_is_zero: 'Placeholder version (0.0.x)',
  meta_version_huge: 'Unusually high major version (dependency confusion tell)',
  meta_n_keywords: 'Number of keywords',
  // Name model features (DESIGN.md section 4.5), with or without a name_ prefix.
  len: 'Name length',
  n_digits: 'Digits in the name',
  n_hyphens: 'Hyphens in the name',
  n_underscores: 'Underscores in the name',
  n_dots: 'Dots in the name',
  min_edit_distance: 'Name is a near-miss of a popular package',
  is_popular: 'Name is a popular package',
  contains_popular_token: 'Name embeds a popular package name',
  scope_squat: 'npm scope imitates a popular scope',
  char_ngram_score: 'Name resembles known malicious names',
  keyboard_typo: 'Name is a keyboard typo of a popular package',
};

const POLICY_RULES: Record<string, string> = {
  min_age_days: 'Version is newer than the minimum age',
  min_age_resolution: 'Resolved to an older version: the newest is younger than the minimum age',
  block_nonexistent: 'Package does not exist on the registry',
  block_install_scripts_from_new: 'Install scripts in a brand-new package',
  provenance_dropped: 'Release lost the provenance attestation earlier releases had',
  install_script_added: 'Release added or changed an install script',
  publisher_changed: 'Release published by an account new to the package',
  dormant_revival: 'First release after a long dormancy',
  version_anomaly: 'Unusual version jump',
  nonregistry_dependency_added: 'Release added a dependency fetched outside the registry',
  young_dependency_added: 'Release added a brand-new dependency from outside the maintainers',
  unread_code: 'Ships code the scanner could not read',
  startup_hook: 'Installs a .pth file that runs code at every Python start',
  scan_error: 'Archive could not be scanned',
  deny: 'Matches the deny list',
  allow: 'Matches the allow list',
  model: 'Model risk above threshold',
  warn_threshold: 'Model risk above the warn threshold',
  block_threshold: 'Model risk above the block threshold',
};

function humanize(id: string): string {
  const s = id.replace(/[_.]+/g, ' ').trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Human-readable label for a model feature id such as `inst_proc_exec`. */
export function featureLabel(feature: string): string {
  const known = FEATURES[feature];
  if (known) return known;
  const name = feature.startsWith('name_') ? feature.slice(5) : null;
  if (name !== null && FEATURES[name]) return FEATURES[name];
  const m = /^(inst|all)_(.+)$/.exec(feature);
  if (m && m[1] && m[2]) {
    const ind = INDICATORS[m[2]];
    if (ind) return `${ind.label} ${m[1] === 'inst' ? 'at install time' : 'somewhere in the package'}`;
  }
  return humanize(feature);
}

export function indicatorLabel(indicator: string): string {
  return INDICATORS[indicator]?.short ?? humanize(indicator);
}

export function indicatorDescription(indicator: string): string {
  return INDICATORS[indicator]?.label ?? humanize(indicator);
}

export function policyRuleLabel(rule: string): string {
  return POLICY_RULES[rule] ?? humanize(rule);
}
