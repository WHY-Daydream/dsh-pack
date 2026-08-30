/**
 * GHCR E2E fixture canonicalization (DESIGN-v0.4.2.md §3/§7, D41–D44;
 * regression 2026-08-30): GitHub owner display names (WHY-Daydream) are NOT
 * valid OCI repository namespace components. The fixture MUST map the owner
 * to a canonical lowercase repository shared by target ref / registry URL /
 * Bearer scope. The generic ImageReference parser keeps rejecting uppercase
 * (see image.spec.ts) — this suite pins the fixture-side mapping only.
 */
import { describe, expect, it } from 'vitest'
import { buildGhcrRepository } from '../scripts/ghcr-fixture.mjs'

describe('buildGhcrRepository（GHCR fixture canonicalization）', () => {
  it('maps a mixed-case GitHub owner to a lowercase OCI repository', () => {
    const fixture = buildGhcrRepository('WHY-Daydream', 'dsh-pack-e2e')
    expect(fixture.repository).toBe('why-daydream/dsh-pack-e2e')
    // target ref and Bearer scope share the SAME canonical repository string
    expect(fixture.remoteRef('run-123')).toBe('ghcr.io/why-daydream/dsh-pack-e2e:run-123')
    expect(fixture.scope()).toBe('repository:why-daydream/dsh-pack-e2e:pull,push')
  })

  it('keeps an already-lowercase owner unchanged', () => {
    const fixture = buildGhcrRepository('why-daydream', 'dsh-pack-e2e')
    expect(fixture.repository).toBe('why-daydream/dsh-pack-e2e')
    expect(fixture.remoteRef('run-456')).toBe('ghcr.io/why-daydream/dsh-pack-e2e:run-456')
    expect(fixture.scope()).toBe('repository:why-daydream/dsh-pack-e2e:pull,push')
  })
})
