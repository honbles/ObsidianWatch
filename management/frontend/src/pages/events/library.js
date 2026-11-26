// The Events query library and the one conversion from search chips to the query language. The Events page,
// the host page's events tab, saved searches and scheduled searches all send a single query string, parsed by
// the server's query language (management/backend/internal/store/event_query.go).
import LIBRARY from './query-library.json'

// [{ group, searches: [{ label, q, needs }] }] in file order. Every query is tested against agent-shaped events
// (store/query_library_pg_test.go).
export const LIBRARY_GROUPS = LIBRARY.reduce((out, e) => {
  let g = out.find(x => x.group === e.group)
  if (!g) out.push(g = { group: e.group, searches: [] })
  g.searches.push({ label: e.label, q: e.q, needs: e.needs })
  return out
}, [])

const quote = (v) => /[\s()"]/.test(v) ? '"' + String(v).replace(/"/g, '\\"') + '"' : String(v)

// One search chip as a query fragment.
export function tagToQuery(t) {
  const v = String(t.value ?? '').trim()
  if (!v) return ''
  switch (t.field) {
    case 'kql': return '(' + v + ')'
    case 'search': return quote(v)
    case 'src_or_dst_ip': return 'ip:' + quote(v)
    case 'dst_port': return 'dstport:' + v
    case 'event_type': return 'type:' + quote(v)
    case 'os': return 'os:' + quote(v)
    case 'severity': return 'sev>=' + v
    case 'proto': return 'proto:' + quote(v)
    case 'source': return 'source:' + quote(v)
    case 'host': return 'host:' + quote(v)
    default: return quote(v)
  }
}

export const tagsToQuery = (tags) => tags.map(tagToQuery).filter(Boolean).join(' ')

// Saved searches used to store chip labels ("OS: windows Type: process Severity: 4"). Same rules as the
// server's NormalizeSavedQuery and migration 082.
export function legacyToQuery(s) {
  return String(s || '')
    .replace(/(^|\s)OS: (\S+)/gi, '$1os:$2').replace(/(^|\s)Type: (\S+)/gi, '$1type:$2')
    .replace(/(^|\s)Severity: ([1-5])/gi, '$1sev>=$2').replace(/(^|\s)IP: (\S+)/gi, '$1ip:$2')
    .replace(/(^|\s)Port: (\d+)/gi, '$1port:$2').replace(/(^|\s)Proto: (\S+)/gi, '$1proto:$2')
    .replace(/(^|\s)Source: (\S+)/gi, '$1source:$2').replace(/(^|\s)Host: (\S+)/gi, '$1host:$2')
}

// A query as a single chip.
export const queryChip = (q) => ({ field: 'kql', label: q, value: q })

// A readable message for a failed search: the server's own words when it gave any.
export function searchError(e) {
  const msg = e?.response?.data?.error
  if (msg) return msg
  if (e?.response?.status === 504) return 'The search took too long. Narrow the time range or add a field condition.'
  if (e?.response) return `The search failed (HTTP ${e.response.status}).`
  return "Can't reach the server."
}
