local DEFAULT_MODEL = "openrouter/free"
local DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
local DEFAULT_CATEGORIES = {
  "information",
  "moteur_de_recherche",
  "jeux",
  "publicite",
  "religieux",
  "mail",
  "telephonie"
}
local JSON_NULL = setmetatable({ }, {
  __tostring = function()
    return "null"
  end
})
local json_escape
json_escape = function(s)
  s = tostring(s)
  s = s:gsub("\\", "\\\\")
  s = s:gsub('"', '\\"')
  s = s:gsub("\n", "\\n")
  s = s:gsub("\r", "\\r")
  s = s:gsub("\t", "\\t")
  return s:gsub("[%z\1-\31]", function(c)
    return string.format("\\u%04x", c:byte())
  end)
end
local is_array
is_array = function(t)
  local n = 0
  for k in pairs(t) do
    if not (type(k) == "number") then
      return false
    end
    n = n + 1
  end
  return n == #t
end
local json_encode
json_encode = function(v)
  local _exp_0 = type(v)
  if "nil" == _exp_0 then
    return "null"
  elseif "boolean" == _exp_0 then
    return v and "true" or "false"
  elseif "number" == _exp_0 then
    return tostring(v)
  elseif "string" == _exp_0 then
    return '"' .. json_escape(v) .. '"'
  elseif "table" == _exp_0 then
    if v == JSON_NULL then
      return "null"
    end
    if is_array(v) then
      local parts = { }
      for _index_0 = 1, #v do
        local item = v[_index_0]
        parts[#parts + 1] = json_encode(item)
      end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      local keys = { }
      for k in pairs(v) do
        keys[#keys + 1] = k
      end
      table.sort(keys, function(a, b)
        return tostring(a) < tostring(b)
      end)
      local parts = { }
      for _index_0 = 1, #keys do
        local k = keys[_index_0]
        parts[#parts + 1] = '"' .. json_escape(tostring(k)) .. '":' .. json_encode(v[k])
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  else
    return "null"
  end
end
local parse_value, parse_object, parse_array
local utf8_encode
utf8_encode = function(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
  elseif cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  else
    return string.char(0xF0 + math.floor(cp / 0x40000), 0x80 + math.floor(cp / 0x1000) % 0x40, 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
end
local skip_ws
skip_ws = function(s, i)
  while i <= #s do
    local c = s:sub(i, i)
    if not (c == " " or c == "\t" or c == "\n" or c == "\r") then
      break
    end
    i = i + 1
  end
  return i
end
local parse_string
parse_string = function(s, i)
  i = i + 1
  local parts = { }
  while i <= #s do
    local c = s:sub(i, i)
    if c == '"' then
      return table.concat(parts), i + 1
    elseif c == "\\" then
      local nc = s:sub(i + 1, i + 1)
      local _exp_0 = nc
      if '"' == _exp_0 then
        parts[#parts + 1] = '"'
      elseif "\\" == _exp_0 then
        parts[#parts + 1] = "\\"
      elseif "/" == _exp_0 then
        parts[#parts + 1] = "/"
      elseif "b" == _exp_0 then
        parts[#parts + 1] = "\b"
      elseif "f" == _exp_0 then
        parts[#parts + 1] = "\f"
      elseif "n" == _exp_0 then
        parts[#parts + 1] = "\n"
      elseif "r" == _exp_0 then
        parts[#parts + 1] = "\r"
      elseif "t" == _exp_0 then
        parts[#parts + 1] = "\t"
      elseif "u" == _exp_0 then
        local hex = s:sub(i + 2, i + 5)
        local code = tonumber(hex, 16)
        if not (code) then
          error("JSON: échappement \\u invalide")
        end
        i = i + 4
        if code >= 0xD800 and code <= 0xDBFF and s:sub(i + 2, i + 3) == "\\u" then
          local hex2 = s:sub(i + 4, i + 7)
          local low = tonumber(hex2, 16)
          if low and low >= 0xDC00 and low <= 0xDFFF then
            code = 0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00)
            i = i + 6
          end
        end
        parts[#parts + 1] = utf8_encode(code)
      else
        error("JSON: échappement invalide \\" .. tostring(nc))
      end
      i = i + 2
    else
      parts[#parts + 1] = c
      i = i + 1
    end
  end
  return error("JSON: chaîne non terminée")
end
parse_value = function(s, i)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  local _exp_0 = c
  if '"' == _exp_0 then
    return parse_string(s, i)
  elseif "{" == _exp_0 then
    return parse_object(s, i)
  elseif "[" == _exp_0 then
    return parse_array(s, i)
  elseif "t" == _exp_0 then
    if not (s:sub(i, i + 3) == "true") then
      error("JSON: littéral invalide")
    end
    return true, i + 4
  elseif "f" == _exp_0 then
    if not (s:sub(i, i + 4) == "false") then
      error("JSON: littéral invalide")
    end
    return false, i + 5
  elseif "n" == _exp_0 then
    if not (s:sub(i, i + 3) == "null") then
      error("JSON: littéral invalide")
    end
    return JSON_NULL, i + 4
  else
    local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
    if num and num ~= "" then
      local n = tonumber(num)
      if not (n) then
        error("JSON: nombre invalide")
      end
      return n, i + #num
    end
    return error("JSON: caractère inattendu '" .. tostring(c) .. "' (pos " .. tostring(i) .. ")")
  end
end
parse_object = function(s, i)
  local obj = { }
  i = skip_ws(s, i + 1)
  if s:sub(i, i) == "}" then
    return obj, i + 1
  end
  while true do
    i = skip_ws(s, i)
    if not (s:sub(i, i) == '"') then
      error("JSON: clé d'objet attendue")
    end
    local key, ni = parse_string(s, i)
    i = skip_ws(s, ni)
    if not (s:sub(i, i) == ":") then
      error("JSON: ':' attendu")
    end
    local val, vi = parse_value(s, i + 1)
    obj[key] = val
    i = skip_ws(s, vi)
    local c = s:sub(i, i)
    if c == "," then
      i = i + 1
    elseif c == "}" then
      return obj, i + 1
    else
      error("JSON: ',' ou '}' attendu")
    end
  end
end
parse_array = function(s, i)
  local arr = { }
  i = skip_ws(s, i + 1)
  if s:sub(i, i) == "]" then
    return arr, i + 1
  end
  while true do
    local val, vi = parse_value(s, i)
    arr[#arr + 1] = val
    i = skip_ws(s, vi)
    local c = s:sub(i, i)
    if c == "," then
      i = i + 1
    elseif c == "]" then
      return arr, i + 1
    else
      error("JSON: ',' ou ']' attendu")
    end
  end
end
local json_decode
json_decode = function(s)
  if not (s and #s > 0) then
    return nil, "entrée vide"
  end
  local ok, val = pcall(parse_value, s, 1)
  if not (ok) then
    return nil, tostring(val)
  end
  return val
end
local sh_quote
sh_quote = function(s)
  return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'"
end
local build_prompt
build_prompt = function(domains, categories)
  categories = categories or DEFAULT_CATEGORIES
  return table.concat({
    "Tu es un expert en classification de sites web, chargé de déterminer à ",
    "quelles catégories appartient un nom de domaine. Un même nom de domaine ",
    "peut appartenir à plusieurs catégories. Réponds UNIQUEMENT par un objet ",
    "JSON valide (sans texte ni bloc de code autour) dont chaque clé est un ",
    "nom de domaine et chaque valeur le tableau des catégories correspondantes ",
    "choisies STRICTEMENT parmi : ",
    table.concat(categories, ", "),
    ". Si aucune catégorie ne convient, renvoie un tableau vide. Domaines à ",
    "classer : ",
    table.concat(domains, ", "),
    "."
  })
end
local build_payload
build_payload = function(model, prompt)
  return table.concat({
    '{"model":"',
    json_escape(model),
    '","messages":[{"role":"user","content":"',
    json_escape(prompt),
    '"}]}'
  })
end
local build_curl_cmd
build_curl_cmd = function(payload, api_key, endpoint, timeout)
  return table.concat({
    "curl --silent --show-error --location --max-time ",
    tostring(timeout),
    " -H " .. sh_quote("Authorization: Bearer " .. tostring(api_key)),
    " -H " .. sh_quote("Content-Type: application/json"),
    " -d " .. sh_quote(payload),
    " " .. sh_quote(endpoint)
  })
end
local request
request = function(prompt, opts)
  opts = opts or { }
  local api_key = opts.api_key or os.getenv("OPENROUTER_API_KEY")
  if not (api_key and api_key ~= "") then
    return nil, "OPENROUTER_API_KEY manquante"
  end
  local model = opts.model or DEFAULT_MODEL
  local endpoint = opts.endpoint or DEFAULT_ENDPOINT
  local timeout = opts.timeout or 60
  local payload = build_payload(model, prompt)
  local cmd = build_curl_cmd(payload, api_key, endpoint, timeout)
  local fh = io.popen(cmd)
  if not (fh) then
    return nil, "io.popen a échoué"
  end
  local body = fh:read("*a")
  local ok = fh:close()
  body = body or ""
  if not (ok and #body > 0) then
    return nil, "curl a échoué (réseau ou timeout)"
  end
  return body
end
local extract_content
extract_content = function(raw)
  local data, err = json_decode(raw)
  if not (data) then
    return nil, "réponse JSON invalide : " .. tostring(err)
  end
  if not (type(data) == "table") then
    return nil, "réponse JSON invalide"
  end
  if data.error then
    local msg
    if type(data.error) == "table" then
      msg = (data.error.message or "erreur API")
    else
      msg = tostring(data.error)
    end
    return nil, "erreur OpenRouter : " .. tostring(msg)
  end
  local choices = data.choices
  if not (type(choices) == "table" and type(choices[1]) == "table") then
    return nil, "réponse sans 'choices'"
  end
  local message = choices[1].message
  if not (type(message) == "table") then
    return nil, "réponse sans 'message'"
  end
  local content = message.content
  if not (type(content) == "string") then
    return nil, "message sans 'content' textuel"
  end
  return content
end
local strip_code_fences
strip_code_fences = function(text)
  local t = text:gsub("^%s+", ""):gsub("%s+$", "")
  local inner = t:match("^```[%w]*%s*(.-)%s*```$")
  if inner then
    return inner
  end
  return t
end
local parse_classification
parse_classification = function(content)
  local json_text = strip_code_fences(content)
  local data, err = json_decode(json_text)
  if not (data) then
    return nil, "classification JSON invalide : " .. tostring(err)
  end
  if not (type(data) == "table" and not is_array(data)) then
    return nil, "la classification n'est pas un objet JSON"
  end
  return data
end
local classify
classify = function(domains, opts)
  opts = opts or { }
  if not (domains and #domains > 0) then
    return nil, "aucun domaine fourni"
  end
  local prompt = build_prompt(domains, opts.categories)
  local raw, err = request(prompt, opts)
  if not (raw) then
    return nil, err
  end
  local content, cerr = extract_content(raw)
  if not (content) then
    return nil, cerr
  end
  local result, perr = parse_classification(content)
  if not (result) then
    return nil, perr
  end
  return result, nil, {
    raw = raw,
    content = content
  }
end
local write_lists
write_lists = function(result, out_dir)
  os.execute("mkdir -p " .. tostring(sh_quote(out_dir)))
  local by_cat = { }
  for domain, cats in pairs(result) do
    if type(cats) == "table" then
      for _index_0 = 1, #cats do
        local c = cats[_index_0]
        local _update_0 = c
        by_cat[_update_0] = by_cat[_update_0] or { }
        by_cat[c][#by_cat[c] + 1] = domain
      end
    end
  end
  local written = { }
  local cats = { }
  for cat in pairs(by_cat) do
    cats[#cats + 1] = cat
  end
  table.sort(cats)
  for _index_0 = 1, #cats do
    local _continue_0 = false
    repeat
      local cat = cats[_index_0]
      local doms = by_cat[cat]
      table.sort(doms)
      local path = tostring(out_dir) .. "/" .. tostring(cat) .. ".txt"
      local fh = io.open(path, "w")
      if not (fh) then
        _continue_0 = true
        break
      end
      local lines = { }
      for _index_1 = 1, #doms do
        local d = doms[_index_1]
        lines[#lines + 1] = d
      end
      fh:write(table.concat(lines, "\n"), "\n")
      fh:close()
      written[#written + 1] = path
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return written
end
local USAGE = [[Usage : OPENROUTER_API_KEY=... luajit lua/classifier.lua [options] domaine...

Options :
  --model M           Modèle OpenRouter (défaut : openrouter/free)
  --categories a,b,c  Catégories cibles séparées par des virgules
  --endpoint URL      Endpoint chat/completions
  --timeout N         Timeout curl en secondes (défaut : 60)
  --out-dir DIR       Écrit aussi DIR/<categorie>.txt par catégorie
  --help              Affiche cette aide

Sans domaine en argument, les domaines sont lus sur l'entrée standard
(un par ligne).]]
local split_csv
split_csv = function(s)
  local out = { }
  for item in tostring(s):gmatch("[^,]+") do
    local v = item:gsub("^%s+", ""):gsub("%s+$", "")
    if v ~= "" then
      out[#out + 1] = v
    end
  end
  return out
end
local parse_args
parse_args = function(argv)
  local opts = {
    domains = { }
  }
  local i = 1
  while argv[i] do
    local a = argv[i]
    local _exp_0 = a
    if "--model" == _exp_0 then
      i = i + 1
      opts.model = argv[i]
    elseif "--endpoint" == _exp_0 then
      i = i + 1
      opts.endpoint = argv[i]
    elseif "--categories" == _exp_0 then
      i = i + 1
      opts.categories = split_csv(argv[i])
    elseif "--timeout" == _exp_0 then
      i = i + 1
      opts.timeout = tonumber(argv[i])
    elseif "--out-dir" == _exp_0 then
      i = i + 1
      opts.out_dir = argv[i]
    elseif "--help" == _exp_0 or "-h" == _exp_0 then
      opts.help = true
    else
      opts.domains[#opts.domains + 1] = a
    end
    i = i + 1
  end
  return opts
end
local read_domains
read_domains = function(fh)
  fh = fh or io.stdin
  local out = { }
  for line in fh:lines() do
    local d = line:gsub("^%s+", ""):gsub("%s+$", "")
    if d ~= "" and not d:match("^#") then
      out[#out + 1] = d
    end
  end
  return out
end
local main
main = function(argv)
  local opts = parse_args(argv or { })
  if opts.help then
    print(USAGE)
    return 0
  end
  local domains = opts.domains
  if #domains == 0 then
    domains = read_domains()
  end
  if #domains == 0 then
    io.stderr:write("Aucun domaine fourni.\n" .. tostring(USAGE) .. "\n")
    return 1
  end
  local result, err, meta = classify(domains, opts)
  if not (result) then
    io.stderr:write("ERREUR : " .. tostring(err) .. "\n")
    return 1
  end
  io.write(json_encode(result), "\n")
  if opts.out_dir then
    local written = write_lists(result, opts.out_dir)
    io.stderr:write(tostring(#written) .. " liste(s) écrite(s) dans " .. tostring(opts.out_dir) .. "/\n")
  end
  return 0
end
if arg and arg[0] and arg[0]:match("classifier%.lua$") then
  os.exit(main(arg))
end
return {
  DEFAULT_MODEL = DEFAULT_MODEL,
  DEFAULT_ENDPOINT = DEFAULT_ENDPOINT,
  DEFAULT_CATEGORIES = DEFAULT_CATEGORIES,
  JSON_NULL = JSON_NULL,
  json_escape = json_escape,
  json_encode = json_encode,
  json_decode = json_decode,
  utf8_encode = utf8_encode,
  is_array = is_array,
  sh_quote = sh_quote,
  build_prompt = build_prompt,
  build_payload = build_payload,
  build_curl_cmd = build_curl_cmd,
  request = request,
  extract_content = extract_content,
  strip_code_fences = strip_code_fences,
  parse_classification = parse_classification,
  classify = classify,
  write_lists = write_lists,
  split_csv = split_csv,
  parse_args = parse_args,
  read_domains = read_domains,
  main = main
}
