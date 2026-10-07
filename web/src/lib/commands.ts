import type { Verdict } from '../api/types';
import { policySpec, shellQuote } from './format';

type PkgRef = Pick<Verdict, 'ecosystem' | 'name' | 'version'>;

/** `customs check` command for a package, shell-quoted because the name is untrusted. */
export function checkCommand(v: PkgRef): string {
  return `customs check ${shellQuote(policySpec(v.ecosystem, v.name, v.version))}`;
}

/** A customs.toml allow line. JSON string escaping is also valid TOML basic-string escaping. */
export function allowlistSnippet(v: PkgRef): string {
  return `allow = [${JSON.stringify(policySpec(v.ecosystem, v.name, v.version))}]`;
}
