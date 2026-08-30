/**
 * dsh-pack plugin entry: registers the `/pack` Human Command family and
 * exposes the `ctx.packager` (DESIGN.md Appendix A) and `ctx.images`
 * (DESIGN-v0.4.md §10) service seams. Commands are executed directly by the
 * UI — never through the model (D12).
 * @module @why-daydream/dsh-pack
 */

import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { makeHandler } from './commands.ts'
import { DefaultImageService } from './image/service.ts'
import { LocalImageStore } from './image/local-store.ts'
import { DefaultEvidenceService } from './evidence/service.ts'
import { resolveDshHome } from './profile-reader.ts'
import { DefaultPackager, readInstalledDshVersion, type PackagerService } from './service.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** The packager service seam (DESIGN.md Appendix A). */
    packager: PackagerService
    /** v0.4 image service seam (DESIGN-v0.4.md §10). */
    images: DefaultImageService
    /** v0.5 evidence service seam (DESIGN-v0.5.0.md §3). */
    evidence: DefaultEvidenceService
  }
}

export const name = 'dsh-pack'

/** Plugin entry: register commands + provide the service seams. */
export const apply = (ctx: Context): (() => void) => {
  const packager = new DefaultPackager()
  ctx.provide('packager', packager)

  const home = resolveDshHome()
  const images = new DefaultImageService(new LocalImageStore(join(home, 'images')), {
    home,
    installedDshVersion: readInstalledDshVersion(),
  })
  ctx.provide('images', images)

  const evidence = new DefaultEvidenceService()
  ctx.provide('evidence', evidence)

  const disposers: (() => void)[] = []
  const handler = makeHandler(packager, images, evidence)
  disposers.push(ctx.commands.register({
    name: 'pack',
    description: 'Pack, inspect, verify, install, sign or run DSH artifacts (.dshpack / images / evidence)',
    input: { hint: '[profile] | inspect <file> | verify <file> | install <file> | sign <file> | keygen | evidence <sign|verify|provenance|sbom|capability|attestation> | image <import|ls|inspect|tag|rm> | run <ref>' },
    handler,
  }))

  return () => {
    for (const dispose of disposers) dispose()
  }
}

export default { name, apply }
