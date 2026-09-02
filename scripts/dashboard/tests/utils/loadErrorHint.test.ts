import { loadErrorHint } from '../../src/utils/loadErrorHint'

describe('loadErrorHint', () => {
  // Measured on a 25,079-finding scan opened as file:///.../dashboard.html:
  // 0 rows, "Loading Failed / Failed to fetch", and the hint "Make sure
  // dashboard-data.json is in the same directory as this HTML file." The file
  // was in the same directory. Chromium's console said
  // `Fetch API cannot load file:///.../dashboard-data.json. URL scheme "file"
  // is not supported.` The same dashboard over HTTP rendered all 25,079.
  it('names the real cause when opened from disk', () => {
    const hint = loadErrorHint('file:')

    expect(hint).toContain('file://')
    expect(hint).toContain('http.server')
  })

  it('does not send the user to check a file that is already there', () => {
    const hint = loadErrorHint('file:')

    expect(hint).not.toContain('same directory')
  })

  it('keeps the original hint when served over HTTP', () => {
    // Over HTTP a fetch failure really is a missing or misplaced file, so the
    // original guidance is correct there and must survive.
    for (const protocol of ['http:', 'https:']) {
      expect(loadErrorHint(protocol)).toContain('same directory')
    }
  })
})
