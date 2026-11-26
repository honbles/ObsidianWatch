# ObsidianWatch brand

The console's identity: the mark, the name, colour, type and voice. How the console implements it is in
[design-language.md](design-language.md).

## Idea

Obsidian is volcanic glass: dark, hard, cut into facets that catch a violet sheen. *Watch* is vigilance.
The brand is a dark faceted frame with one violet accent, around an interface that stays calm until
something needs attention. Colour is spent on state, never on decoration.

## Mark and name

| Asset | File | Use |
|---|---|---|
| Mark | `management/frontend/public/favicon.svg`, `OWMark` in `src/components/Shell.jsx` | Favicon, header, setup page |
| Lockup (mark and wordmark on the chrome colour) | `management/frontend/src/assets/logo.svg` | Documentation, slides, anything outside the console |
| Wordmark | `OWWordmark` in `src/components/Shell.jsx` | Next to the mark in the console |

- **Mark.** The shard eye: two obsidian blades form the eyelids and the pupil is a cut gem, so the mark says
  *obsidian* and *watch* in one shape. Each blade has a lit and a shaded facet; it is drawn with six flat shapes on a
  24-unit grid so it stays sharp at 16 px. The shapes and colours live in `MARK_SHAPES` / `MARK` in
  `src/utils/brand.js` (and the same paths in `public/favicon.svg` and `src/assets/logo.svg`); the mark looks the
  same in both themes.
- **Wordmark.** "Obsidian" semibold, "Watch" regular at 72% opacity, set in IBM Plex Sans with slightly
  tight tracking. One word, capital O and capital W: *ObsidianWatch*.
- Do not recolour, outline, rotate or add effects to the mark, and do not put it on a busy background.
  On light backgrounds use the lockup file, which carries its own chrome-coloured plate.

## Colour

### Brand

| Name | Hex | Use |
|---|---|---|
| Iris (brand) | `#7c5cff` | The mark, brand moments |
| Iris deep | `#5b3df5` | Primary buttons, links and focus in the light theme |
| Iris light | `#a896ff` | Links, focus and the active marker on dark surfaces |
| Obsidian (chrome) | `#13101f` | Rail, context bar, the brand panel of the signed-out pages |

### Chrome

The header keeps the obsidian frame in **both** themes (`--ch-*` tokens). Only the content
area changes with the theme. This is what makes the console recognisable at a glance, in the way
Splunk's dark bar is.

| Token | Hex | Use |
|---|---|---|
| `--ch-bg` | `#13101f` | Frame background |
| `--ch-2` / `--ch-3` | `#1d1931` / `#2a2347` | Hover / active item |
| `--ch-line` | `#2b2643` | Frame borders |
| `--ch-t1` / `--ch-t2` / `--ch-t3` | `#f3f0fd` / `#b6afd3` / `#8b85a9` | Text, strong to quiet |
| `--ch-acc` | `#a896ff` | Active marker, icons of the active item |

### Content surfaces

Neutrals carry a faint violet cast so the frame and the content read as one material.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0c0b11` | `#f3f2f8` | Page canvas |
| `--s1` | `#14131b` | `#ffffff` | Cards, page headers, tables |
| `--s2` / `--s3` | `#1a1923` / `#23212e` | `#f9f8fc` / `#efedf5` | Table heads, hover, raised fills |
| `--line` / `--line2` | `#2b2938` / `#3a3749` | `#e3e0ec` / `#ccc7da` | Borders, quiet / strong |
| `--t1` / `--t2` / `--t3` | `#eceaf4` / `#aca8bd` / `#868299` | `#16131f` / `#4c475e` / `#67627c` | Text, strong to quiet |

In the light theme, cards and tiles get a soft shadow (`--shadow-card`), so they lift off the grey canvas.
The dark theme separates surfaces by tone alone.

### State and severity

Colour is reserved for state. Every state also has a shape (circle, diamond, square) and a word, so colour
is never the only signal.

| Meaning | Token | Dark | Light |
|---|---|---|---|
| OK | `--ok` | `#3dd68c` | `#12803f` |
| Warning, medium severity | `--warn` (`--med`) | `#f5bd45` | `#a56b00` |
| High severity | `--high` | `#ff8b42` | `#c0520a` |
| Critical | `--crit` | `#ff6369` | `#c8242f` |
| Low severity, information | `--info` (`--low`) | `#5ca8ff` | `#1d6dd1` |
| Unknown, info severity | `--t3` | | |

Platform severity 5..1 is `--sev5` (critical) to `--sev1` (info): five distinct colours, so high and medium
no longer look alike.

### Charts

Series take colours in this order: `--cat1` violet, `--cat2` teal, `--cat3` blue, `--cat4` magenta, `--cat5` amber,
`--cat6` cyan, `--cat7` orange, `--cat8` grey (`CAT` in `src/utils/colors.js`). A chart about severity uses the
severity colours instead.

## Type

- **IBM Plex Sans** for the interface: engineered, slightly condensed, very legible at 12–13 px.
- **IBM Plex Mono** for data: hosts, routes, hashes, IDs, ARNs, commands, counts in badges.
- Both are bundled (Latin and Latin Extended, SIL Open Font License, `src/assets/fonts/OFL.txt`), so an
  air-gapped console renders exactly like a connected one. Tabular figures are on everywhere.
- Weights: 400 body, 500 emphasis and active navigation, 600 titles and numbers. No 700 in the interface.

## Voice

- Sentence case for titles, buttons, tabs and labels: "Change password", not "Change Password".
- Say what is true. A status in the interface comes from the server ("Server reachable"), never a fixed
  claim ("System operational").
- Errors say what happened and what to do next.
- Short. A page carries facts and consequences; explanations of how a feature works belong in the docs.
- Icons come from the console's icon set (Lucide). No emoji as icons; typographic marks (✓ ⚠ ✗) are fine in text.
