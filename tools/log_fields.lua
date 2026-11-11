-- tools/log_fields.lua
-- Inventaire statique des noms de champs des tables littérales passées aux
-- appels de log (`log_xxx -> { ... }`, `write_log ..., -> { ... }`,
-- `log_xxx -> with_meta { ... }`). Utilisé par le test garde-fou
-- `tests/unit/log_fields_spec.moon` : tout champ extrait doit être classé
-- explicitement dans `src/log.moon` (identité ou volatil).
--
-- Les thunks qui renvoient une variable (`log_info -> fields`) ne peuvent pas
-- être inventoriés statiquement : le garde-fou ne couvre que les tables
-- littérales. Les champs de ces tables construites ailleurs restent traités
-- comme identité par défaut à l'exécution (prudence).

local M = {}

local function read_file(path)
  local f = assert(io.open(path, "r"))
  local s = f:read("*a")
  f:close()
  return s
end

local function list_moon_files(root)
  local files = {}
  local p = io.popen("find '" .. root .. "' -name '*.moon' -type f | sort")
  if not p then return files end
  for line in p:lines() do
    files[#files + 1] = line
  end
  p:close()
  return files
end

-- Si `j` ouvre une chaîne longue Lua (`[[...]]`, `[=[...]=]`), retourne
-- l'index qui suit sa fermeture ; nil sinon.
local function long_bracket_end(s, j)
  local eq = s:sub(j):match("^%[(=*)%[")
  if eq == nil then return nil end
  local close = "]" .. eq .. "]"
  local p = s:find(close, j + #eq + 2, true)
  return p and (p + #close) or (#s + 1)
end

-- Retourne le corps d'un `{...}` équilibré (sans les accolades) et l'index qui
-- suit l'accolade fermante. Ignore chaînes et commentaires `--`.
local function balanced_braces(s, i)
  assert(s:sub(i, i) == "{", "balanced_braces attend une accolade")
  local depth = 0
  local j = i
  while j <= #s do
    local c = s:sub(j, j)
    local lbe = (c == "[" and long_bracket_end(s, j)) or nil
    if lbe then
      j = lbe
    elseif c == '"' or c == "'" then
      local quote = c
      j = j + 1
      while j <= #s do
        local d = s:sub(j, j)
        if d == "\\" then
          j = j + 2
        elseif d == quote then
          break
        else
          j = j + 1
        end
      end
      j = j + 1
    elseif c == "-" and s:sub(j + 1, j + 1) == "-" then
      local nl = s:find("\n", j, true)
      j = (nl or #s) + 1
    elseif c == "{" then
      depth = depth + 1
      j = j + 1
    elseif c == "}" then
      depth = depth - 1
      if depth == 0 then
        return s:sub(i + 1, j - 1), j + 1
      end
      j = j + 1
    else
      j = j + 1
    end
  end
  error("accolade non équilibrée à l'offset " .. i)
end

-- Extrait les clés de premier niveau d'un corps de table. Les clés des tables
-- imbriquées (valeurs `{...}`) sont ignorées : seuls les champs du message
-- comptent.
local function keys_in_body(body)
  local keys = {}
  local depth = 0
  local j = 1
  while j <= #body do
    local c = body:sub(j, j)
    local lbe = (c == "[" and long_bracket_end(body, j)) or nil
    if lbe then
      j = lbe
    elseif c == '"' or c == "'" then
      local quote = c
      j = j + 1
      while j <= #body do
        local d = body:sub(j, j)
        if d == "\\" then
          j = j + 2
        elseif d == quote then
          break
        else
          j = j + 1
        end
      end
      j = j + 1
    elseif c == "-" and body:sub(j + 1, j + 1) == "-" then
      local nl = body:find("\n", j, true)
      j = (nl or #body) + 1
    elseif c == "{" then
      depth = depth + 1
      j = j + 1
    elseif c == "}" then
      depth = depth - 1
      j = j + 1
    elseif depth == 0 and (c:match("[%a_]") or c:match("[%d]")) then
      local word = body:match("^[%w_]+", j)
      local after = j + #word
      -- Clé de table : identifiant suivi de `:` (mais pas `::`).
      local sep = body:match("^[ \t]*:", after)
      if sep and body:sub(after + #sep + 1, after + #sep + 1) ~= ":" then
        keys[word] = true
        j = after + #sep + 1
      else
        j = after
      end
    else
      j = j + 1
    end
  end
  return keys
end

-- Parcourt tous les littéraux `{...}` de premier niveau du texte (les tables
-- imbriquées sont incluses dans le corps de leur parent, pas visitées à part).
local function each_table(text, fn)
  local j = 1
  while j <= #text do
    local c = text:sub(j, j)
    local lbe = (c == "[" and long_bracket_end(text, j)) or nil
    if lbe then
      j = lbe
    elseif c == '"' or c == "'" then
      local quote = c
      j = j + 1
      while j <= #text do
        local d = text:sub(j, j)
        if d == "\\" then
          j = j + 2
        elseif d == quote then
          break
        else
          j = j + 1
        end
      end
      j = j + 1
    elseif c == "-" and text:sub(j + 1, j + 1) == "-" then
      local nl = text:find("\n", j, true)
      j = (nl or #text) + 1
    elseif c == "{" then
      local body, nxt = balanced_braces(text, j)
      fn(body)
      j = nxt
    else
      j = j + 1
    end
  end
end

-- Extrait les champs d'un source MoonScript. Retourne un ensemble name -> true.
--
-- Deux sources :
--  1. les tables directement passées à un appel de log (`log_xxx -> { ... }`,
--     `log_xxx -> with_meta { ... }`) ;
--  2. toute table littérale portant une clé `action:` de log, y compris quand
--     elle est construite hors du thunk (`log_info -> build_orphan_fields {…}`,
--     corps de `build_orphan_fields`). Une valeur d'action commençant par `/`
--     est une action de formulaire HTML (`H.form { action: "/login" }`), pas un
--     événement de log : ces tables sont ignorées.
function M.extract(text)
  local found = {}
  local init = 1
  while true do
    local a, b = text:find("log_[%a_]+%s*%-%>%s*", init)
    if not a then break end
    local p = b + 1
    if text:sub(p, p + 8) == "with_meta" then
      p = p + 9
      while text:sub(p, p):match("%s") do p = p + 1 end
    end
    if text:sub(p, p) == "{" then
      local body, nxt = balanced_braces(text, p)
      for k in pairs(keys_in_body(body)) do
        found[k] = true
      end
      init = nxt
    else
      -- Thunk non littéral (`-> fields`, expression…) : rien à inventorier ici ;
      -- la seconde passe couvre les tables `action:` construites ailleurs.
      init = b + 1
    end
  end

  each_table(text, function(body)
    local keys = keys_in_body(body)
    if keys.action then
      local action = body:match('action:%s*"([^"]*)"')
      if action and action:sub(1, 1) ~= "/" then
        for k in pairs(keys) do
          found[k] = true
        end
      end
    end
  end)

  return found
end

-- Parcourt récursivement `root` et retourne l'ensemble des champs trouvés.
function M.scan(root)
  local found = {}
  for _, path in ipairs(list_moon_files(root)) do
    local fields = M.extract(read_file(path))
    for k in pairs(fields) do
      found[k] = true
    end
  end
  return found
end

return M
