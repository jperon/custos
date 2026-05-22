local css
css = function()
  return [[*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px; line-height: 1.5; color: #222;
  background: #f5f5f5; padding: 1rem 2rem;
}

a { color: #0070d2; text-decoration: none; }
a:hover { text-decoration: underline; }

h1 { font-size: 1.4rem; margin-bottom: 1rem; }
h2 { font-size: 1.1rem; margin: 1rem 0 .5rem; }
h3 { font-size: 1rem; margin: .8rem 0 .3rem; color: #444; }

nav { margin-bottom: 1rem; padding: .5rem; background: #fff;
      border: 1px solid #ddd; border-radius: 4px; }
nav a { margin-right: 1rem; }

section { background: #fff; border: 1px solid #ddd; border-radius: 4px;
          padding: 1rem; margin-bottom: 1rem; }

details { background: #fff; border: 1px solid #ddd; border-radius: 4px;
          margin-bottom: .4rem; }
details > summary { padding: .5rem 1rem; cursor: pointer; font-weight: 600;
                    list-style: none; user-select: none; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: '▶ '; font-size: .75em; color: #888; }
details[open] > summary::before { content: '▼ '; }
details[open] > summary { border-bottom: 1px solid #eee; }
details > :not(summary) { padding: .75rem 1rem; }

table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { text-align: left; padding: .4rem .6rem;
         border-bottom: 1px solid #eee; vertical-align: top; }
th { background: #f0f0f0; font-weight: 600; font-size: .85rem; color: #555; }
tr:last-child td { border-bottom: none; }

label { display: block; font-weight: 500; margin-bottom: .25rem; }
input[type=text], input[type=password], input[type=number],
input[type=email], input[type=time], select, textarea {
  width: 100%; padding: .4rem .6rem; border: 1px solid #ccc;
  border-radius: 4px; font-size: 14px; margin-bottom: .75rem;
  background: #fff;
}
textarea { min-height: 5rem; font-family: monospace; resize: vertical; }
input[type=checkbox] { width: auto; margin-right: .4rem; }

fieldset { border: 1px solid #ddd; border-radius: 4px;
           padding: .75rem 1rem; margin-bottom: .75rem; }
legend { padding: 0 .4rem; font-weight: 600; font-size: .9rem; color: #555; }

button, .btn {
  display: inline-block; padding: .4rem .9rem; border: 1px solid #0070d2;
  background: #0070d2; color: #fff; border-radius: 4px; cursor: pointer;
  font-size: 14px; text-decoration: none;
}
button:hover, .btn:hover { background: #005bb5; }
button.secondary, .btn-secondary {
  background: #fff; color: #0070d2;
}
button.secondary:hover, .btn-secondary:hover { background: #f0f7ff; }
button.danger, .btn-danger {
  background: #c0392b; border-color: #c0392b;
}
button.danger:hover, .btn-danger:hover { background: #a93226; }

.btn-sm { padding: .25rem .6rem; font-size: 12px; }

.flash {
  padding: .6rem 1rem; border-radius: 4px; margin-bottom: 1rem;
  border: 1px solid;
}
.flash.info    { background: #e8f4fd; border-color: #bee3f8; color: #1a5276; }
.flash.success { background: #eafaf1; border-color: #a9dfbf; color: #1e8449; }
.flash.warning { background: #fef9e7; border-color: #f9e79f; color: #7d6608; }
.flash.error   { background: #fdedec; border-color: #f5b7b1; color: #922b21; }

td.mono { font-family: monospace; font-size: .85rem; color: #555; }
td.actions { white-space: nowrap; text-align: right; }

.hidden { display: none; }
]]
end
return {
  css = css
}
