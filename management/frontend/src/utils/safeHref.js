// safeHref returns the URL only if it is plain http(s); anything else
// (javascript:, data:, vbscript:, relative junk) becomes "#". Use it for any
// href that originates from provider/API data rather than our own code.
export function safeHref(url) {
  if (typeof url !== 'string') return '#'
  try {
    const u = new URL(url.trim())
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : '#'
  } catch {
    return '#'
  }
}

// cveHref builds an NVD link, encoding the id so odd data can't alter the URL.
export function cveHref(cve) {
  return 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(String(cve))
}
