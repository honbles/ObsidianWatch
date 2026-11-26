// Applies the saved theme and display size before the console renders, so it never flashes.
// First visit: theme follows the operating system; display size is Default. The console stores choices later.
(function () {
  try {
    var el = document.documentElement
    var t = localStorage.getItem('ow-theme')
    if (t !== 'light' && t !== 'dark') t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    if (t === 'light') el.classList.add('light')
    var d = localStorage.getItem('ow-display')
    if (d === 'compact' || d === 'large') el.classList.add('ds-' + d)
  } catch (e) { /* storage unavailable: defaults */ }
})()
