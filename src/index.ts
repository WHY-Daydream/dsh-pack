/**
 * dsh-pack plugin entry: registers the `/pack` Human Command family and
 * exposes the `ctx.packager` service seam (DESIGN.md Appendix A). Commands are
 * executed directly by the UI — never through the model (D12).
 * @module @why-daydream/dsh-pack
 */

import type { Context } from '@deepseek-ai/cordis'
import { DefaultPackager, type PackagerService } from './service.ts'
import { makeHandler } from './commands.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** The packager service seam (DESIGN.md Appendix A). */
    packager: PackagerService
  }
}

export const name = 'dsh-pack'

/** Plugin entry: register commands + provide the service seam. */
export const apply = (ctx: Context): (() => void) => {
  const packager = new DefaultPackager()
  ctx.provide('packager', packager)

  const disposers: (() => void)[] = []
  const handler = makeHandler(packager)
  disposers.push(ctx.commands.register({
    name: 'pack',
    description: 'Pack, inspect, verify or install DSH Profile snapshots (.dshpack)',
    input: { hint: '[profile] | inspect <file> | verify <file> | install <file>' },
    handler,
  }))

  return () => {
    for (const dispose of disposers) dispose()
  }
}

export default { name, apply }
