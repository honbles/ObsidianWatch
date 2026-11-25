# Console design language

Source: *ObsidianWatch Console Redesign* (design language, Endpoint fleet, Application service,
Code repositories, Cloud posture boards). This file records how the console implements it.

## Foundations (`management/frontend/src/index.css`)

- **Type.** Inter for the interface, JetBrains Mono for data (routes, hashes, paths, commands, ARNs, IDs).
  Both ship in `src/assets/fonts` (Latin and Latin Extended, OFL, see `OFL.txt`), so an air-gapped console
  renders the same. Tabular figures are on globally.
- **Colour.** Graphite surfaces `--bg --s1 --s2 --s3`, borders `--line --line2`, text `--t1 --t2 --t3`,
  one accent `--acc`. State colours `--ok --warn --crit` (plus `--*bg` tints) are used for state only.
  Dark and light (`html.light`) use the same names.
- **Compatibility.** The old names (`--surface`, `--text2`, `--red`, `siem-*` Tailwind colours…) are aliases
  of the new tokens, and saturated Tailwind/inline state colours are pulled onto the state tokens, so pages not
  yet rebuilt still follow the palette.

## State

Five states, each with a word and a shape so colour is never the only signal:
OK (circle), Warning (diamond), Critical (square), Unknown/offline (grey circle), Info (accent circle).
Platform severity maps as: 5 Critical, 4 High (warning colour), 3 Medium (info colour), 2 Low, 1 Info.

| Page | Rule |
|---|---|
| Fleet host | Online or Offline only. Hosts carry no health verdict; open alerts are a separate column (count and worst severity) linking to the alerts. |
| Service | error rate ≥ 5% or SLO budget spent: Failing. Error rate ≥ 1%, p95 over target, < 25% budget, or an open alert: Degraded. No traffic: Unknown. |
| Repository / cloud finding | worst open finding's severity. |

The pill's tooltip states which rule applied.

## Parts (`src/components/ui.jsx`)

`PageHeader` (title, state pill, sub-line, actions, headline numbers, tabs) · `Num` · `StatTile` · `Tabs` ·
`StatePill` / `SevPill` · `StateBar` · `Meter` · `Facets` + `countBy` + `useFacetFilter` ·
`DenseTable` (38 px rows, state stripe) · `parseFilter` (`key:value` filter syntax) · `relTime` · `downloadCSV` · `Trend`.

## Shell (`src/components/Shell.jsx`)

Left rail grouped by domain (Endpoint, Application, Code, Cloud, Detect, Administration),
collapsible to icons, with fleet reachability at the foot. Context bar: breadcrumb, global search
(Ctrl/⌘ K or `/`: pages, hosts, services, then event search or hunt), time range (only on pages that read
`?from=&to=`, currently Applications), theme, open alerts, user menu.

## Page patterns

| Pattern | Model | Pages |
|---|---|---|
| Tactical overview: domain × (total, problems, critical, stale), every count a link; one unhandled-problems list across domains | Checkmk | Overview |
| Incident review: status tabs (unhandled / in progress / closed), urgency, owner, response-target age, charts toggle, checkbox commands (acknowledge, assign, close with comment), detail side panel | Splunk ES | Alerts |
| Explorer: query + time range on one line, timeline over the whole query (click to zoom), facets that add real filters, dense rows, side panel | Datadog Log Explorer | Events |
| Catalogue: facets + dense table + selection bar + side panel | Datadog | Rules, Fleet, Services, Repositories, Cloud posture, Alert rules, Suppressions, Audit log, Users |

Shared explorer parts in `components/ui.jsx`: `Histogram`, `Drawer`, `SelectionBar`, `useSelection`, `Dialog`, `Field`, `Section`, `Check`;
`DenseTable` takes `selected/onSelect/onSelectAll`, `current`, `sort/onSort`. State rules live in `utils/states.js`.

## Backend addition

`GET /api/v1/events/summary` (`management/backend/internal/api/events_summary.go`, `store/events_summary.go`): counts per
time bucket and severity, and the top values of host, event type, source, user and process, over every event matching the
query. Same parameters, 90-day lookback clamp and 10 s timeout as `/events/search`. The Events page falls back to a
clearly labelled page-only timeline if the endpoint is missing.

## Status

Rebuilt with the parts: shell, Overview, Alerts, Events, Fleet, service detail, Services, Code, Cloud, Rules,
Alert rules, Suppressions, Users, Audit log. Standard header and tabs: Hunt, Insights, Platform settings, Agent builder,
Network, all Applications pages. Workspace layouts kept (restyled by tokens): Search, Live response, host detail tabs,
per-connector Code and Cloud workspaces, Sigma and threat-intel panels.

Navigation rule: a row that names a thing opens that thing's page (repository, finding, cloud finding, trace, error,
alert); nothing expands inline below a table. Response is one page (`/response`): pick hosts, pick an action, review,
run; history and live response sit beside it. Hosts are grouped by tags only (no host groups); policies will target tags.

Differences from the boards, because the data does not exist: Fleet shows tamper protection and tags
instead of CPU, mode and policies; there is no global environment selector; Cloud shows the existing risk score
(lower is better) and pass rate; Code has no pipeline-change or unreviewed-merge counts.
