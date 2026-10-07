import { describe, expect, it } from 'vitest';
import { allowlistSnippet, checkCommand } from './commands';
import { featureLabel, indicatorLabel } from './features';
import {
  formatCount,
  formatPercent,
  formatSigned,
  hasInvisible,
  isValidPackageName,
  parsePackageSpec,
  registryUrl,
  relativeTime,
  revealInvisible,
  safeLabel,
  safeSnippet,
  shellQuote,
  shortSha,
  truncate,
  truncateMiddle,
} from './format';

const RLO = String.fromCharCode(0x202e);
const ZWSP = String.fromCharCode(0x200b);
const ELLIPSIS = String.fromCharCode(0x2026);

describe('truncation', () => {
  it('truncates long strings with an ellipsis', () => {
    expect(truncate('abcdef', 10)).toBe('abcdef');
    expect(truncate('abcdef', 4)).toBe(`abc${ELLIPSIS}`);
    expect(truncateMiddle('src/very/long/path/file.py', 12)).toBe(`src/ve${ELLIPSIS}le.py`);
  });

  it('caps snippets by lines and characters', () => {
    const many = Array.from({ length: 30 }, (_, i) => `line ${i}`).join('\n');
    const s = safeSnippet(many, 1000, 5);
    expect(s.split('\n')).toHaveLength(5);
    expect(s.endsWith(ELLIPSIS)).toBe(true);
    expect(safeSnippet('x'.repeat(2000), 100)).toHaveLength(101);
  });
});

describe('invisible characters', () => {
  it('reveals bidi overrides and zero-width characters', () => {
    const s = `if (a) {/*${RLO} } ${ZWSP}*/`;
    expect(hasInvisible(s)).toBe(true);
    expect(revealInvisible(s)).toBe('if (a) {/*<U+202E> } <U+200B>*/');
    expect(hasInvisible('plain text')).toBe(false);
  });

  it('reveals control characters but keeps tabs and newlines', () => {
    const esc = String.fromCharCode(27);
    expect(revealInvisible(`a${esc}[31mb\tc\nd`)).toBe('a<U+001B>[31mb\tc\nd');
  });

  it('safeLabel collapses newlines', () => {
    expect(safeLabel('a\nb', 10)).toBe('a b');
  });
});

describe('registry links', () => {
  it('builds PyPI and npm URLs from validated names only', () => {
    expect(registryUrl('pypi', 'requests')).toBe('https://pypi.org/project/requests/');
    expect(registryUrl('npm', 'react')).toBe('https://www.npmjs.com/package/react');
    expect(registryUrl('npm', '@types/node')).toBe('https://www.npmjs.com/package/@types/node');
  });

  it('refuses names that are not package names', () => {
    expect(registryUrl('pypi', 'javascript:alert(1)')).toBeNull();
    expect(registryUrl('npm', '../../evil')).toBeNull();
    expect(registryUrl('pypi', 'a b')).toBeNull();
    expect(registryUrl('cargo', 'serde')).toBeNull();
    expect(isValidPackageName('npm', '@scope/name')).toBe(true);
    expect(isValidPackageName('pypi', '-leading')).toBe(false);
  });
});

describe('commands', () => {
  it('quotes untrusted values for the shell', () => {
    expect(shellQuote('pypi:requests@2.32.3')).toBe('pypi:requests@2.32.3');
    expect(shellQuote('x; rm -rf ~')).toBe("'x; rm -rf ~'");
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
  });

  it('builds check and allowlist snippets', () => {
    expect(checkCommand({ ecosystem: 'pypi', name: 'reqeusts', version: '2.32.4' })).toBe('customs check pypi:reqeusts@2.32.4');
    expect(checkCommand({ ecosystem: 'npm', name: 'a$(id)', version: null })).toBe("customs check 'npm:a$(id)'");
    expect(allowlistSnippet({ ecosystem: 'npm', name: '@lodash-utils/core', version: '4.17.22' })).toBe(
      'allow = ["npm:@lodash-utils/core@4.17.22"]',
    );
    expect(allowlistSnippet({ ecosystem: 'npm', name: 'a"b', version: null })).toBe('allow = ["npm:a\\"b"]');
  });

  it('parses pinned package specs', () => {
    expect(parsePackageSpec('pypi', 'requests==2.32.3')).toEqual({ name: 'requests', version: '2.32.3' });
    expect(parsePackageSpec('pypi', 'requests[socks]')).toEqual({ name: 'requests', version: null });
    expect(parsePackageSpec('npm', '@types/node@22.7.4')).toEqual({ name: '@types/node', version: '22.7.4' });
    expect(parsePackageSpec('npm', '@types/node')).toEqual({ name: '@types/node', version: null });
    expect(parsePackageSpec('npm', 'react@18.3.1')).toEqual({ name: 'react', version: '18.3.1' });
  });
});

describe('number formatting', () => {
  it('formats percentages and counts', () => {
    expect(formatPercent(0.993)).toBe('99.3%');
    expect(formatPercent(0.5)).toBe('50%');
    expect(formatPercent(0.0004)).toBe('<0.1%');
    expect(formatPercent(null)).toBe('n/a');
    expect(formatCount(1234)).toBe('1,234');
    expect(formatCount(12900)).toBe('12.9K');
    expect(formatSigned(1.84)).toBe('+1.84');
    expect(formatSigned(-0.2)).toBe(`${String.fromCharCode(0x2212)}0.20`);
    expect(shortSha('abcdef0123456789')).toBe('abcdef012345');
  });

  it('formats relative times', () => {
    const now = Date.parse('2026-10-07T12:00:00Z');
    expect(relativeTime('2026-10-07T11:59:55Z', now)).toBe('just now');
    expect(relativeTime('2026-10-07T11:59:30Z', now)).toBe('30s ago');
    expect(relativeTime('2026-10-07T11:59:00Z', now)).toBe('1 min ago');
    expect(relativeTime('2026-10-07T11:00:00Z', now)).toBe('1 h ago');
    expect(relativeTime('2026-10-05T12:00:00Z', now)).toBe('2 d ago');
  });
});

describe('feature labels', () => {
  it('labels known and unknown features', () => {
    expect(featureLabel('inst_proc_exec')).toBe('Runs shell commands at install time');
    expect(featureLabel('all_network')).toBe('Makes network requests somewhere in the package');
    expect(featureLabel('name_keyboard_typo')).toBe('Name is a keyboard typo of a popular package');
    expect(featureLabel('meta_version_huge')).toMatch(/dependency confusion/);
    expect(featureLabel('brand_new_thing')).toBe('Brand new thing');
    expect(indicatorLabel('exfil_endpoint')).toBe('Exfil endpoint');
  });
});
