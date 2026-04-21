-- SPDX-License-Identifier: MIT
-- Copyright (c) 2025 jperon

--- Concise HTML DSL.
-- `h = require "auth.html"` then `h.<tag> ...` returns an HTML string.
-- Each call accepts any mix of:
--   * tables — array part = children, key/value part = attributes
--   * strings / numbers — appended as children
--   * functions — called with no argument, result appended as child
-- Tags without children render as self-closing (`<br/>`).
--
-- Example:
--   with require "auth.html"
--     print .div id: "test", class: "example",
--       "Hello ", .em "world!"
-- @module auth.html

concat   = table.concat
remove   = table.remove
insert   = table.insert

--- Renders an HTML tag.
-- @tparam string tag Tag name (e.g. "div", "br")
-- @param ...  Children (string/number/function) or attribute tables
-- @treturn string Rendered HTML
render_tag = (tag, ...) ->
  children = {}
  attrs    = {}

  for i = 1, select "#", ...
    arg = select i, ...
    t   = type arg
    switch t
      when "table"
        -- Array part → children (consumed in order)
        while #arg > 0
          insert children, remove arg, 1
        -- Remaining pairs → attributes
        for k, v in pairs arg
          insert attrs, " #{k}=\"#{v}\""
      when "function"
        insert children, arg!
      when "string", "number"
        insert children, arg

  attr_html = concat attrs
  if #children == 0
    "<#{tag}#{attr_html}/>"
  else
    "<#{tag}#{attr_html}>#{concat children, '\n'}</#{tag}>"

html = {}
setmetatable html, __index: (k) =>
  (...) -> render_tag k, ...
html
