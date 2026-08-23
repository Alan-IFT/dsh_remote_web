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

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'

/** How long to wait for another process to finish its update. */
const LOCK_TIMEOUT_MS = 5_000
/** After this, a lock is assumed to belong to a process that died. */
const LOCK_STALE_MS = 30_000
/** Gap between attempts while waiting. */
const LOCK_POLL_MS = 10

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
      // No `dsh-remote-web:` prefix here; the CLI's failure path adds it, and
      // naming the tool twice reads like a bug in the tool.
      throw new Error(
        `${this.#path} is unreadable (${detail}). Fix or remove the file before continuing.`,
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
   * Reading current state is only half of that guarantee. Another process can
   * write between this read and this write, and a plain write would erase it —
   * the same resurrected revocation in a new guise.
   *
   * The window is small: one read-modify-write here is well under a
   * millisecond, and the relay writes on attach and login rather than on every
   * request, so an unlucky overlap is rare. It is guarded anyway because of
   * what is lost rather than how often. The operation at risk is revocation,
   * which is invoked exactly when a credential is compromised, reports success
   * either way, and competes with the attacker's own attach and login traffic —
   * so the load that opens the window is correlated with the incident. Batch
   * writers lose updates outright regardless of timing.
   *
   * So the whole read-modify-write is serialized by an exclusive lock. The
   * {@link value} stamp cannot stand in for one: a touch rewrites a timestamp,
   * leaving the file the same size within the same millisecond, so the two
   * writes are indistinguishable to `stat`. The stamp keeps a reader current,
   * which is what it is for; it cannot detect a concurrent writer.
   *
   * `mkdir` is the lock because it is atomic on every POSIX filesystem and on
   * Windows, needs no dependency, and leaves a visible artifact an operator can
   * delete. A stale lock from a killed process expires, so a crash cannot wedge
   * the tool permanently.
   *
   * @param mutate - Receives current state; return value is persisted.
   * @returns Whatever `mutate` reports, for callers that need a result.
   */
  update<R>(mutate: (current: T) => { next: T; result: R }): R {
    const release = this.#lock()
    try {
      const { next, result } = mutate(this.value)
      this.write(next)
      return result
    } finally {
      release()
    }
  }

  /**
   * Take the write lock, waiting for a holder and breaking a stale one.
   *
   * The wait is a blocking sleep because every caller here is synchronous: the
   * CLI is a short-lived command, and the relay's store writes are small and
   * infrequent relative to a request. Making this async would recolor the whole
   * store API for a lock held over a few milliseconds of JSON.
   */
  #lock(): () => void {
    const dir = `${this.#path}.lock`
    const deadline = Date.now() + LOCK_TIMEOUT_MS
    for (;;) {
      try {
        mkdirSync(dir, { recursive: false })
        return () => {
          try {
            rmSync(dir, { recursive: true, force: true })
          } catch {
            // Already gone: another process broke it as stale. Nothing to undo.
          }
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
      // Break a lock whose owner died, so a crash mid-update cannot wedge every
      // later command. The window is generous relative to the work it guards.
      try {
        if (Date.now() - statSync(dir).mtimeMs > LOCK_STALE_MS) {
          rmSync(dir, { recursive: true, force: true })
          continue
        }
      } catch {
        continue // Vanished while we looked; try to take it.
      }
      if (Date.now() > deadline) {
        throw new Error(
          `timed out waiting for ${dir}. ` +
            'Another process is writing; remove that directory if none is.',
        )
      }
      // Sleep without a busy loop; Atomics.wait is the synchronous primitive.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LOCK_POLL_MS)
    }
  }

  /** Whether the file exists on disk. */
  get exists(): boolean {
    return existsSync(this.#path)
  }
}
