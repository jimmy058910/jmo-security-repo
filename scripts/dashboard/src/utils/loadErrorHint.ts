/**
 * Guidance shown under a dashboard data-loading failure.
 *
 * The external-data dashboard (written when a scan exceeds the inline
 * threshold) loads `dashboard-data.json` with `fetch()`. Browsers refuse
 * `fetch()` against a `file://` URL — Chromium reports
 * `URL scheme "file" is not supported` — so double-clicking dashboard.html
 * fails for exactly the large scans that produce the external mode.
 *
 * The old hint was "Make sure dashboard-data.json is in the same directory as
 * this HTML file." Measured on a 25,079-finding scan, the file WAS in the same
 * directory: the instruction sent the user to check something that was already
 * true, and said nothing about the actual cause. The same dashboard served over
 * HTTP rendered all 25,079 findings across 1,004 pages.
 *
 * @param protocol - `window.location.protocol`, e.g. `"file:"` or `"http:"`.
 * @returns The hint to display beneath the error.
 */
export function loadErrorHint(protocol: string): string {
  if (protocol === 'file:') {
    return (
      'This dashboard loads its data with fetch(), which browsers block for ' +
      'file:// URLs. Serve the directory over HTTP instead — for example, run ' +
      '"python3 -m http.server 8000" in this folder and open ' +
      'http://localhost:8000/dashboard.html'
    )
  }
  return 'Make sure dashboard-data.json is in the same directory as this HTML file.'
}
