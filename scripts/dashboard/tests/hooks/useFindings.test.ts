import { renderHook, waitFor } from '@testing-library/react'
import { useFindings } from '../../src/hooks/useFindings'

// write_html (scripts/core/reporters/html_reporter.py) has two modes. Up to
// INLINE_THRESHOLD findings it writes them into the page and sets
// window.__FINDINGS_INLINE__; above it, it leaves window.__FINDINGS__ = [] and
// writes dashboard-data.json beside the page. The hook must tell the two apart
// by that mark, because the array alone cannot: a scan with no findings writes
// the same [] that external mode leaves behind (#1710).

type DashboardWindow = Window & {
  __FINDINGS__?: unknown
  __FINDINGS_INLINE__?: unknown
}

const w = window as DashboardWindow

const finding = {
  schemaVersion: '1.2.0',
  id: 'f1',
  ruleId: 'R1',
  severity: 'HIGH',
  message: 'one finding',
  tool: { name: 'trivy', version: '0.0.0' },
  location: { path: 'app.py', startLine: 1 },
}

let fetchMock: jest.Mock

beforeEach(() => {
  // A fetch that answers as `python -m http.server` does for a file that is
  // not there, which is what external mode met for a scan with no findings.
  fetchMock = jest.fn().mockResolvedValue({
    ok: false,
    status: 404,
    statusText: 'File not found',
    json: async () => ({}),
  })
  global.fetch = fetchMock as unknown as typeof fetch
})

afterEach(() => {
  delete w.__FINDINGS__
  delete w.__FINDINGS_INLINE__
})

describe('useFindings, current scan', () => {
  it('reads an inline report with no findings as zero findings, not a load failure', async () => {
    w.__FINDINGS_INLINE__ = true
    w.__FINDINGS__ = []

    const { result } = renderHook(() => useFindings())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBeNull()
    expect(result.current.findings).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('reads inline findings from the page', async () => {
    w.__FINDINGS_INLINE__ = true
    w.__FINDINGS__ = [finding]

    const { result } = renderHook(() => useFindings())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBeNull()
    expect(result.current.findings).toEqual([finding])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('fetches dashboard-data.json when the page is not marked inline', async () => {
    // External mode: the placeholder stays [] and the data is in a file.
    w.__FINDINGS__ = []
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => [finding],
    })

    const { result } = renderHook(() => useFindings())

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(fetchMock).toHaveBeenCalledWith('dashboard-data.json')
    expect(result.current.error).toBeNull()
    expect(result.current.findings).toEqual([finding])
  })
})
