/**
 * The shared-state primitive.
 *
 * These tests pin the property that eliminated a whole bug class: two
 * processes hold separate handles to one file, and neither may serve or
 * resurrect stale data. The relay/CLI split relies on exactly this.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { WatchedFile } from '../src/shared/watched-file.js'

interface Doc {
  version: 1
  items: string[]
}

let dir: string
let path: string

/** Open an independent handle, as a separate process would. */
function open(): WatchedFile<Doc> {
  return new WatchedFile<Doc>(
    path,
    (raw) => {
      const value = raw as Doc
      if (value?.version !== 1 || !Array.isArray(value.items)) {
        throw new Error('unrecognized shape')
      }
      return value
    },
    () => ({ version: 1, items: [] }),
  )
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-watched-'))
  path = join(dir, 'state.json')
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('basics', () => {
  it('uses the fallback until the file exists', () => {
    const file = open()
    expect(file.exists).toBe(false)
    expect(file.value).toEqual({ version: 1, items: [] })
  })

  it('round-trips a written value', () => {
    const file = open()
    file.write({ version: 1, items: ['a'] })
    expect(file.value).toEqual({ version: 1, items: ['a'] })
    expect(file.exists).toBe(true)
  })

  it('writes owner-only', () => {
    const file = open()
    file.write({ version: 1, items: [] })
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  it('throws on unreadable content rather than returning the fallback', () => {
    writeFileSync(path, '{not json')
    // Silently treating corruption as "empty" would revoke every credential.
    expect(() => open().value).toThrow(/unreadable/)
  })

  it('throws when the parser rejects the shape', () => {
    writeFileSync(path, JSON.stringify({ version: 99 }))
    expect(() => open().value).toThrow(/unrecognized shape/)
  })
})

describe('cross-handle consistency', () => {
  it('sees a write made through another handle', () => {
    const a = open()
    const b = open()
    expect(a.value.items).toEqual([])

    b.write({ version: 1, items: ['from-b'] })

    expect(a.value.items).toEqual(['from-b'])
  })

  it('does not resurrect data another handle removed', () => {
    const relay = open()
    relay.write({ version: 1, items: ['keep', 'remove-me'] })
    // The relay has read and cached this value.
    expect(relay.value.items).toHaveLength(2)

    open().write({ version: 1, items: ['keep'] })

    // The exact bug this class prevents: a later write from the stale holder
    // must not restore the removed entry.
    relay.update((current) => ({
      next: { ...current, items: [...current.items] },
      result: null,
    }))
    expect(open().value.items).toEqual(['keep'])
  })

  it('applies update() to current state, not a previously read snapshot', () => {
    const a = open()
    a.write({ version: 1, items: ['one'] })
    void a.value

    open().write({ version: 1, items: ['one', 'two'] })

    a.update((current) => ({
      next: { ...current, items: [...current.items, 'three'] },
      result: null,
    }))
    expect(open().value.items).toEqual(['one', 'two', 'three'])
  })

  it('detects a same-millisecond rewrite of different size', () => {
    const reader = open()
    reader.write({ version: 1, items: ['a'] })
    expect(reader.value.items).toEqual(['a'])
    // mtime alone can collide within one clock tick, so size participates in
    // the stamp; without it a rapid edit would be missed.
    writeFileSync(path, JSON.stringify({ version: 1, items: ['a', 'bbbbbbbb'] }))
    expect(reader.value.items).toEqual(['a', 'bbbbbbbb'])
  })

  it('returns the result of update()', () => {
    const file = open()
    file.write({ version: 1, items: [] })
    const added = file.update((current) => ({
      next: { ...current, items: [...current.items, 'x'] },
      result: 'added' as const,
    }))
    expect(added).toBe('added')
  })

  it('serializes updates so concurrent writers cannot erase each other', () => {
    // The shape of a lost revocation: the relay reads state to stamp a
    // last-seen time, an operator revokes in that window, and the relay writes
    // its copy back over the revocation. The stamp cannot detect this — a
    // timestamp rewrite leaves the file the same size within the same
    // millisecond — so update() holds a lock across read and write.
    //
    // Real concurrent processes, because that is the only way to contend for
    // the lock: a same-process handle would deadlock, and sequential calls
    // cannot reproduce a race at all. Each writer appends under update(), and
    // every append must survive — a lost update silently drops some.
    // Driven through the built RelayStore: it is the real caller, it is the
    // only WatchedFile reachable from a plain `node`, and CI already fails if
    // that build is stale. The writer goes to a file rather than `-e` so no
    // quoting has to survive a trip through the shell.
    const relay = fileURLToPath(new URL('../lib/relay.js', import.meta.url))
    const script = join(dir, 'writer.mjs')
    writeFileSync(
      script,
      `const { RelayStore } = await import(${JSON.stringify(relay)})\n` +
        `const store = new RelayStore(process.env.TARGET)\n` +
        `for (let i = 0; i < 30; i += 1) store.createAgent(process.env.TAG + i)\n`,
    )
    const spawn = ['a', 'b', 'c']
      .map((tag) => `TAG=${tag} "${process.execPath}" "${script}" &`)
      .join(' ')
    const run = spawnSync('sh', ['-c', `${spawn} wait`], {
      env: { ...process.env, TARGET: path },
      encoding: 'utf8',
    })
    expect(run.stderr).toBe('')

    const state = JSON.parse(readFileSync(path, 'utf8')) as { agents: unknown[] }
    expect(state.agents).toHaveLength(90)
  })

  it('leaves no lock behind', () => {
    const file = open()
    file.write({ version: 1, items: [] })
    file.update((c) => ({ next: { ...c, items: ['x'] }, result: null }))
    expect(existsSync(`${path}.lock`)).toBe(false)
  })

  it('breaks a lock left by a process that died', () => {
    const file = open()
    file.write({ version: 1, items: [] })
    mkdirSync(`${path}.lock`)
    // Backdate it well past the staleness window.
    const old = new Date(Date.now() - 120_000)
    utimesSync(`${path}.lock`, old, old)

    file.update((current) => ({ next: { ...current, items: ['ok'] }, result: null }))
    expect(open().value.items).toEqual(['ok'])
  })
})
