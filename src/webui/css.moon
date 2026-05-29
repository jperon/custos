-- src/webui/css.moon
-- CSS minimal classless, injecté en <style> dans chaque page.

css = -> [[
:root {
  --bg: #f4f6f9;
  --surface: #ffffff;
  --border: #e2e6ea;
  --border-strong: #cdd3da;
  --text: #1f2933;
  --muted: #66707a;
  --accent: #0070d2;
  --accent-hover: #005bb5;
  --accent-soft: #eaf3fd;
  --danger: #c0392b;
  --danger-hover: #a93226;
  --radius: 8px;
  --shadow: 0 1px 2px rgba(16, 24, 40, .04), 0 1px 3px rgba(16, 24, 40, .06);
  --shadow-hover: 0 2px 6px rgba(16, 24, 40, .08), 0 4px 12px rgba(16, 24, 40, .06);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { -webkit-text-size-adjust: 100%; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 15px; line-height: 1.55; color: var(--text);
  background: var(--bg);
  padding: 1.25rem;
  max-width: 1100px; margin: 0 auto;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

h1 { font-size: 1.5rem; font-weight: 650; letter-spacing: -.01em; margin-bottom: 1.25rem; }
h2 { font-size: 1.15rem; font-weight: 620; margin: .25rem 0 .75rem; }
h3 { font-size: 1rem; font-weight: 600; margin: .9rem 0 .4rem; color: var(--muted); }

p { margin-bottom: .6rem; }
p:last-child { margin-bottom: 0; }

/* Navigation */
nav {
  display: flex; flex-wrap: wrap; gap: .25rem;
  margin-bottom: 1.5rem; padding: .4rem;
  background: var(--surface);
  border: 1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow);
}
nav a {
  padding: .45rem .8rem; border-radius: 6px;
  color: var(--muted); font-weight: 550;
  white-space: nowrap; transition: background .12s, color .12s;
}
nav a:hover { background: var(--accent-soft); color: var(--accent); text-decoration: none; }

/* Cartes */
section, details {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow);
  margin-bottom: 1rem;
}
section { padding: 1.25rem; }

details { margin-bottom: .5rem; transition: box-shadow .12s; }
details[open] { box-shadow: var(--shadow-hover); }
details > summary {
  padding: .7rem 1rem; cursor: pointer; font-weight: 600;
  list-style: none; user-select: none;
  display: flex; align-items: center; gap: .5rem;
  border-radius: var(--radius);
}
details > summary:hover { background: var(--accent-soft); }
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: '▸'; font-size: .9em; color: var(--muted);
  transition: transform .12s;
}
details[open] > summary::before { transform: rotate(90deg); }
details[open] > summary {
  border-bottom: 1px solid var(--border);
  border-radius: var(--radius) var(--radius) 0 0;
}
details > :not(summary) { padding: 1rem; }

/* Tables — défilables sur mobile */
table {
  border-collapse: collapse; width: 100%; margin: .5rem 0;
  display: block; overflow-x: auto;
}
th, td {
  text-align: left; padding: .55rem .7rem;
  border-bottom: 1px solid var(--border); vertical-align: top;
}
th {
  background: #f7f9fb; font-weight: 600; font-size: .8rem;
  text-transform: uppercase; letter-spacing: .03em; color: var(--muted);
}
tbody tr { transition: background .1s; }
tbody tr:hover { background: #fafbfc; }
tr:last-child td { border-bottom: none; }

/* Formulaires */
label { display: block; font-weight: 550; margin-bottom: .3rem; font-size: .9rem; }
input[type=text], input[type=password], input[type=number],
input[type=email], input[type=time], select, textarea {
  width: 100%; padding: .5rem .65rem;
  border: 1px solid var(--border-strong); border-radius: 6px;
  font-size: 15px; margin-bottom: .85rem; background: var(--surface);
  color: var(--text); transition: border-color .12s, box-shadow .12s;
}
input:focus, select:focus, textarea:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
textarea { min-height: 6rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; resize: vertical; }
input[type=checkbox] { width: auto; margin-right: .45rem; accent-color: var(--accent); }

fieldset {
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 1rem; margin-bottom: 1rem;
}
legend { padding: 0 .5rem; font-weight: 600; font-size: .85rem; color: var(--muted); }

/* Boutons */
button, .btn {
  display: inline-block; padding: .5rem 1rem;
  border: 1px solid var(--accent); background: var(--accent); color: #fff;
  border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 550;
  text-decoration: none; transition: background .12s, box-shadow .12s;
}
button:hover, .btn:hover { background: var(--accent-hover); text-decoration: none; }
button:focus-visible, .btn:focus-visible {
  outline: none; box-shadow: 0 0 0 3px var(--accent-soft);
}
button.secondary, .btn-secondary { background: var(--surface); color: var(--accent); }
button.secondary:hover, .btn-secondary:hover { background: var(--accent-soft); }
button.danger, .btn-danger { background: var(--danger); border-color: var(--danger); }
button.danger:hover, .btn-danger:hover { background: var(--danger-hover); }

.btn-sm { padding: .3rem .7rem; font-size: 12.5px; }

/* Bandeaux flash */
.flash {
  padding: .7rem 1rem; border-radius: var(--radius); margin-bottom: 1rem;
  border: 1px solid; font-weight: 500;
}
.flash.info    { background: #e8f4fd; border-color: #bee3f8; color: #1a5276; }
.flash.success { background: #eafaf1; border-color: #a9dfbf; color: #1e8449; }
.flash.warning { background: #fef9e7; border-color: #f9e79f; color: #7d6608; }
.flash.error   { background: #fdedec; border-color: #f5b7b1; color: #922b21; }

td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; color: var(--muted); }
td.actions { white-space: nowrap; text-align: right; }

.hidden { display: none; }

/* Responsive */
@media (max-width: 640px) {
  body { padding: .75rem; font-size: 14.5px; }
  h1 { font-size: 1.3rem; }
  section { padding: 1rem; }
  nav { gap: .15rem; }
  nav a { padding: .4rem .6rem; }
}
]]

{ :css }
