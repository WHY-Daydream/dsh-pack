/**
 * v0.4 Image Reference grammar (DESIGN-v0.4.md §3, D21/D22):
 * `[registry/][namespace/]name[:tag][@digest]` — Docker-compatible syntax.
 * Frozen: tag is a mutable alias; digest is the immutable content identity
 * (`sha256:` + 64 hex, same family as contentHash). Parsing never guesses:
 * invalid references throw ImageReferenceError (exit 1 upstream).
 * @module @why-daydream/dsh-pack/image/reference
 */

export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const NAME_SEGMENT_RE = /^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*$/
const TAG_RE = /^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$/

/** A parsed image reference (DESIGN-v0.4.md §3). */
export interface ImageReference {
  /** host[:port] — present when the first path component contains '.'/':' or is 'localhost'. */
  registry?: string
  /** namespace path (empty for single-segment names). */
  namespace: string
  /** final path component. */
  name: string
  /** mutable human alias (optional). */
  tag?: string
  /** immutable content identity (optional). */
  digest?: string
}

/** Invalid image reference (parse failure → exit 1 upstream). */
export class ImageReferenceError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ImageReferenceError'
  }
}

/** Whether a digest string matches `sha256:<64 hex>`. */
export function validateDigest(digest: string): boolean {
  return DIGEST_RE.test(digest)
}

/** Parse an image reference; throws ImageReferenceError on any violation. */
export function parseReference(ref: string): ImageReference {
  if (typeof ref !== 'string' || ref.trim() === '') {
    throw new ImageReferenceError('empty image reference')
  }
  const input = ref.trim()

  // digest: split at the LAST '@'
  let rest = input
  let digest: string | undefined
  const at = rest.lastIndexOf('@')
  if (at !== -1) {
    digest = rest.slice(at + 1)
    rest = rest.slice(0, at)
    if (!DIGEST_RE.test(digest)) {
      throw new ImageReferenceError(`invalid digest ${JSON.stringify(digest)} (expect sha256:<64 hex>)`)
    }
  }

  // tag: split at the LAST ':' AFTER the last '/'
  let tag: string | undefined
  const slash = rest.lastIndexOf('/')
  const colon = rest.lastIndexOf(':')
  if (colon > slash) {
    tag = rest.slice(colon + 1)
    rest = rest.slice(0, colon)
    if (!TAG_RE.test(tag)) throw new ImageReferenceError(`invalid tag ${JSON.stringify(tag)}`)
  }

  // path: [registry/]namespace.../name — never guess: leading, double or
  // trailing slashes are invalid forms; reject instead of silently normalizing.
  if (rest.startsWith('/') || rest.endsWith('/') || rest.includes('//')) {
    throw new ImageReferenceError(`invalid image reference ${JSON.stringify(input)} (leading, double or trailing slash)`)
  }
  const parts = rest.split('/')
  // '.' / '..' segments are traversal attempts — reject BEFORE the registry
  // heuristic (a '..' would otherwise be swallowed as a dot-containing host).
  for (const segment of parts) {
    if (segment === '.' || segment === '..') {
      throw new ImageReferenceError(`invalid image reference ${JSON.stringify(input)} (path traversal)`)
    }
  }
  if (parts.length === 0) throw new ImageReferenceError(`missing image name in ${JSON.stringify(input)}`)
  const name = parts[parts.length - 1] as string
  if (!NAME_SEGMENT_RE.test(name)) {
    throw new ImageReferenceError(`invalid image name ${JSON.stringify(name)} (lowercase [a-z0-9] with . _ - separators)`)
  }
  const head = parts.slice(0, -1)
  let registry: string | undefined
  let namespaceParts = head
  const first = head[0]
  if (first !== undefined && (first.includes('.') || first.includes(':') || first === 'localhost')) {
    registry = first
    namespaceParts = head.slice(1)
  }
  for (const segment of namespaceParts) {
    if (!NAME_SEGMENT_RE.test(segment)) {
      throw new ImageReferenceError(`invalid namespace component ${JSON.stringify(segment)}`)
    }
  }

  return {
    ...(registry !== undefined ? { registry } : {}),
    namespace: namespaceParts.join('/'),
    name,
    ...(tag !== undefined ? { tag } : {}),
    ...(digest !== undefined ? { digest } : {}),
  }
}

/** The repository part (registry + namespace + name), e.g. `ghcr.io/why-daydream/agent`. */
export function repository(ref: ImageReference): string {
  const parts = [
    ...(ref.registry !== undefined ? [ref.registry] : []),
    ...(ref.namespace !== '' ? [ref.namespace] : []),
    ref.name,
  ]
  return parts.join('/')
}

/** Canonical display form (includes tag/digest when present). */
export function formatReference(ref: ImageReference): string {
  let out = repository(ref)
  if (ref.tag !== undefined) out += `:${ref.tag}`
  if (ref.digest !== undefined) out += `@${ref.digest}`
  return out
}

/** Immutable form: `repo@sha256:<digest>` (never a tag). */
export function digestReference(ref: ImageReference): string {
  if (ref.digest === undefined) throw new ImageReferenceError('reference carries no digest')
  return `${repository(ref)}@${ref.digest}`
}
