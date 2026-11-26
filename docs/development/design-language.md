# Console design language

Source: *ObsidianWatch Console Redesign* (design language, Endpoint fleet, Application service,
Code repositories, Cloud posture boards). This file records how the console implements it.

## Foundations (`management/frontend/src/index.css`)

Brand, colours and type are described in [brand.md](brand.md). This section is how the console applies them.

- **Tokens.** Every colour is a CSS custom property. Each is defined once per theme as RGB channels
  (`--crit-c: 255 99 105`) and resolved for use (`--crit: rgb(var(--crit-c))`), so both CSS and Tailwind can
  add transparency. The two themes differ only in the token block at the top of `index.css`; nothing else in
  the console says "if light".
- **Names.** Surfaces `--bg --s1 --s2 --s3`, borders `--line --line2`, text `--t1 --t2 --t3`, accent `--acc`
  (links, focus, selection) and `--accf` (filled buttons), state `--ok --warn --high --crit --info` with
  `--okbg --wbg --hbg --cbg --ibg` tints, severity `--sev5`..`--sev1`, chart series `--cat1`..`--cat8`,
  chrome `--ch-*`. The older names (`--surface`, `--text2`, `--red`, `siem-*` Tailwind colours…) remain as
  aliases.
- **Tailwind palette.** `tailwind.config.js` rebuilds Tailwind's colour names on the tokens: red and rose are
  critical, orange is high, amber and yellow are warning, green, emerald and lime are OK, blue and sky are
  information, cyan, violet, indigo and purple are the brand accent, gray, slate and zinc are the neutrals.
  Shades keep their intent: 50–600 the colour, 700–800 a border tone, 900–950 the base for tinted backgrounds
  (`bg-red-950/30`). There is no other palette to reach for.
- **Type.** IBM Plex Sans for the interface, IBM Plex Mono for data. Both ship in `src/assets/fonts`.
- **Depth.** Cards, tiles and stat panels use `--shadow-card` (a soft shadow in light, none in dark);
  menus and dialogs use `--shadow-pop`.

## Themes

- Dark and light. The theme button in the context bar (and on the signed-out pages) switches them; the choice
  is stored in the browser (`ow-theme`).
- A first visit with nothing stored follows the operating system's preference. `public/theme-init.js` applies
  the theme before the first paint, so the console never flashes the other one; `src/api/useTheme.js` uses the
  same rule.
- Terminals (live response, host terminal) stay dark in both themes (`TERMINAL_THEME` in `src/utils/brand.js`).

## Display size

- The whole console is drawn at a scale, `--ui-zoom` on the root element: **Compact** 1 (the size before November 2026),
  **Default** 1.08, **Large** 1.16. People choose it under **Display size** in the user menu; the browser remembers it
  (`ow-display`) and `public/theme-init.js` applies it before the first paint. Helpers: `src/utils/display.js`.
- Use `--vh` / `--vw` (`calc(100 * var(--vh))`) instead of `vh` / `vw`: they stay one percent of the window at any scale.
- Pointer positions are in window pixels. Code that subtracts positions by hand (`clientX - rect.left`, drag
  distances) divides by `uiZoom()`. Ratios, d3 on SVG and Recharts need nothing.
- Terminals and Leaflet maps do their own pointer maths, so they render at native scale inside `.ow-nozoom-fill`.

## Rules for components

- **No raw colours.** Use a token (`var(--crit)`, `var(--t2)`), a design-system class (`ow-pill crit`,
  `c-warn`) or the Tailwind palette. `npm run build` runs `scripts/check-colours.mjs` first and fails on any
  hex, `rgb()` or `hsl()` colour in `src/` (black and white `rgba()` overlays are allowed). The only file
  allowed fixed colours is `src/utils/brand.js` (mark, chrome, terminal).
- **Transparency of a token:** `tint('var(--crit)', 15)` from `src/utils/colors.js` (a `color-mix`), or
  `rgb(var(--crit-c) / .15)`. Never append hex alpha to a colour string.
- **Canvas** cannot read CSS variables: pass colours through `resolveColor()` from `src/utils/colors.js` at draw time.
  SVG attributes take tokens directly (`fill="var(--ok)"`).
- **Severity** colours come from `SEV_COLORS` / `sevState()` in `components/ui.jsx` (pills, stripes, charts) or
  `SEV_VAR` in `utils/colors.js`. Chart series take `CAT` in order.
- **Icons** come from `lucide-react`. Emoji are not used as icons.
- **Copy.** Pages state facts, limits and consequences in a line; how-to explanations live in the docs. Empty states
  say what is empty ("No routes yet."), not how to fill them. Page subtitles are one short line or left out.

## State

Five states, each with a word and a shape so colour is never the only signal:
OK (circle), Warning (diamond), Critical (square), Unknown/offline (grey circle), Info (accent circle).
Platform severity has its own five colours and maps as: 5 Critical (`crit`, square), 4 High (`high`, diamond),
3 Medium (`med`, amber circle), 2 Low (`low`, blue circle), 1 Info (grey circle).

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

Navigation is a header in the chrome colours (both themes), so pages always use the full width.

- **Products.** The mark (and wordmark from 1600 px), Overview, then one menu per product: **Endpoint** (Fleet, Hunt,
  Prevention, Response, with fleet reachability at the foot), **Application** (Hosts, Overview, Services, Dependencies,
  Coverage, Settings), **Code** (Repositories), **Cloud** (Posture), **Network** (Probes, beta), **ITDR** (announced:
  its items are marked "soon" and link nowhere), and **Detect** across all of them (Alerts with the open count, Events,
  Insights, Rules, Alert rules, Suppressions). The product of the current page is underlined.
- **Menus.** Click opens a menu; while one is open, hovering another product switches to it. Choosing a page, clicking
  elsewhere or Escape closes it. The menu list lives in `buildNav()`.
- **Tools** on the right: search (Ctrl/⌘ K or `/`: pages, hosts, services, then event search or hunt), the time range
  (only on pages that read `?from=&to=`, currently Applications), theme, open alerts, **Settings** (admins: Agent builder,
  Users and access, Audit log, Platform settings) and the user menu (Display size, Change password, Sign out).
- Under 1280 px the product menus fold into one **Menu** button that lists every product.

## Signed-out pages

- **Sign in** (`pages/Login.jsx`) is a dark obsidian stage in both themes (the `.force-dark` class re-resolves the
  tokens in the dark theme). An animated network runs behind it (violet endpoints, teal servers, red threats,
  traffic between them). In the middle is a large eye that fades into the stage at its edges, breathes slowly and whose
  iris turns once every 90 s. On the left: the headline and the six domains (Endpoint, Application, Code, Cloud, Network,
  ITDR); on the right, the form card. No logo on this page. Motion stops when the system asks for reduced motion;
  under 880 px only the card shows. The form has username, password with show/hide, a Caps Lock hint, the server's
  error message, and whether the server answered (from `/api/v1/setup/status`). Sign-ins and failed attempts are
  recorded in the audit log. A wrong password shows the error in place; a 401 from `/auth/login` or `/auth/password`
  does not end the session (`src/api/client.js`).
- **First-run setup** (`pages/Setup.jsx`, also `/setup?rerun=1`) uses `src/components/AuthLayout.jsx`: brand panel on
  the left (chrome colours), form on the right following the theme. Detected network, connection URLs, optional AI
  and threat-intelligence keys.
- **Change password** (`pages/ChangePassword.jsx`) runs inside the shell. When a password change is required it
  says so first; after the change it returns to the Overview.

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

Brand and themes (November 2026): every page reads the tokens, so dark and light are complete across the
console; the sign-in, setup and change-password pages are rebuilt on the shared layout.

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
