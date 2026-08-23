/**
 * A JSON file that reloads itself when it changes on disk.
 *
 * Two independent processes share this package's state files: the long-running
 * relay (or DSH plugin) holds one view while a short-lived CLI command edits
 * another. A cached snapshot is therefore not merely stale — it is dangerous,
 * because the holder will write its stale copy back and silently undo the
 * edit. That is exactly how a revocation was once resurrected.
 *
 * The fix is structural rather than disciplinary. Reads go through a getter
 * that checks the file stamp first, so *every* access is current by
 * construction; there is no "remember to refresh" rule for a future edit to
 * forget.
 *
 * @module dsh-remote-web/shared/watched-file
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'

/**
 * Owner-only JSON file whose in-memory value tracks the file on disk.
 *
 * @typeParam T - Shape stored in the file.
 */
export class WatchedFile<T> {
  readonly #path: string
  readonly #parse: (raw: unknown) => T
  readonly #fallback: () => T
  #stamp = ''
  #value: T | null = null

  /**
   * @param path - File location; parent directories are created on write.
   * @param parse - Validates and normalizes parsed JSON. Throw to reject a
   *                file whose shape is not understood; callers see the throw
   *                rather than a silently empty value.
   * @param fallback - Value used when the file does not exist yet.
   */
  constructor(path: string, parse: (raw: unknown) => T, fallback: () => T) {
    this.#path = path
    this.#parse = parse
    this.#fallback = fallback
  }

  /** Absolute path of the backing file. */
  get path(): string {
    return this.#path
  }

  /**
   * Identity of the file's current contents.
   *
   * Size joins mtime because two writes can land in the same millisecond here:
   * a CLI command and the relay may both write within one clock tick.
   */
  #currentStamp(): string {
    try {
      const stats = statSync(this.#path)
      return `${String(stats.mtimeMs)}:${String(stats.size)}`
    } catch {
      return ''
    }
  }

  /**
   * The current value, re-read when the file changed since the last access.
   *
   * Cost in the steady state is one `stat`; a parse happens only when the
   * stamp actually moved.
   */
  get value(): T {
    const stamp = this.#currentStamp()
    if (stamp !== this.#stamp || this.#value === null) {
      this.#stamp = stamp
      this.#value = this.#read()
    }
    return this.#value
  }

  #read(): T {
    if (!existsSync(this.#path)) return this.#fallback()
    let parsed: unknown
    try {
      parsed = JSON.parse(readFileSync(this.#path, 'utf8'))
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(
        `dsh-remote-web: ${this.#path} is unreadable (${detail}). ` +
          'Fix or remove the file before continuing.',
      )
    }
    return this.#parse(parsed)
  }

  /**
   * Replace the file's contents atomically with mode `0600`.
   *
   * Temp-file-plus-rename means a crash mid-write cannot leave a truncated
   * file, which for a credential store would lock the operator out.
   */
  write(value: T): void {
    const dir = dirname(this.#path)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const tmp = join(dir, `.${randomUUID()}.tmp`)
    writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 })
    renameSync(tmp, this.#path)
    try {
      chmodSync(this.#path, 0o600)
    } catch {
      // Some filesystems (mounted volumes, Windows shares) refuse chmod.
    }
    // Adopt our own write so the next read does not treat it as foreign.
    this.#value = value
    this.#stamp = this.#currentStamp()
  }

  /**
   * Apply a mutation to the current value and persist the result.
   *
   * The read is deliberately inside this method: mutating a value fetched
   * earlier would reintroduce the lost-update bug this class exists to
   * prevent.
   *
   * @param mutate - Receives current state; return value is persisted.
   * @returns Whatever `mutate` reports, for callers that need a result.
   */
  update<R>(mutate: (current: T) => { next: T; result: R }): R {
    const { next, result } = mutate(this.value)
    this.write(next)
    return result
  }

  /** Whether the file exists on disk. */
  get exists(): boolean {
    return existsSync(this.#path)
  }
}
