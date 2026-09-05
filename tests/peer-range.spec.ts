import { createRequire } from 'node:module'
import { describe, expect, it } from 'vitest'
import semver from 'semver'

const require = createRequire(import.meta.url)
const manifest = require('../package.json') as {
  peerDependencies: Record<string, string>
}

/**
 * The supported DSH line declared as a peer range (0.1.x only; 0.2.x is never
 * auto-opened — run the compatibility matrix first, then widen deliberately).
 *
 * npm semver prerelease rule: a prerelease candidate only satisfies a range if
 * SOME comparator in the matched set shares its major.minor.patch tuple and is
 * itself a prerelease (e.g. `0.1.2-rc.1` needs a `(0,1,2)`-tuple prerelease
 * comparator). A bare `>=0.1.0-rc.5` therefore EXCLUDES every later 0.1.x
 * prerelease line (npm ERESOLVE when DSH ships `0.1.2-rc.1` / `0.1.3-alpha.1`),
 * and so does a single `>=0.1.0-rc.5 <0.2.0-0` window. One range cannot express
 * "all future 0.1.x prereleases", so every released / in-source DSH prerelease
 * line (0.1.0 from rc.5, the published 0.1.1-rc.x, 0.1.2-rc.x, in-source
 * 0.1.3-alpha.1) is added as an explicit `>=X-0` union member.
 * Do NOT collapse these members back into a single `<0.2.0-0`-bounded range —
 * the regression list below is the compatibility contract to keep green.
 */
const RANGE = manifest.peerDependencies['@deepseek-ai/dsh-app-boot']

describe('peer range @deepseek-ai/dsh-app-boot (latest-DSH compatibility)', () => {
  it('declares the supported DSH 0.1.x window', () => {
    expect(RANGE).toBe('>=0.1.0-rc.5 <0.2.0-0 || >=0.1.1-0 <0.2.0-0 || >=0.1.2-0 <0.2.0-0 || >=0.1.3-0 <0.2.0-0')
  })

  it.each([
    // in-window — MUST stay true
    ['0.1.0-rc.5', true], // lower bound itself
    ['0.1.0-rc.6', true], // npm `latest` at fix time
    ['0.1.0-rc.8', true], // 0.1.0 prerelease line
    ['0.1.1-rc.1', true], // published 0.1.1 line (superseded but released)
    ['0.1.1-rc.2', true], // published 0.1.1 line (superseded but released)
    ['0.1.2-rc.1', true], // latest npm DSH family (`next` tag) — FAILS with a single-window range
    ['0.1.2-alpha.5', true], // npm `alpha` tag family
    ['0.1.3-alpha.1', true], // latest GitHub source — FAILS with a single-window range
    ['0.1.0', true], // first stable
    ['0.1.4', true], // future 0.1.x stable
    // out of window — MUST stay false
    ['0.1.0-rc.4', false], // below the lower bound
    ['0.2.0-alpha.1', false], // 0.2.x prerelease — never auto-opened
    ['0.2.0', false], // 0.2.x stable — never auto-opened
  ])('matches %s → %s', (version, expected) => {
    expect(semver.satisfies(version, RANGE)).toBe(expected)
  })
})
