-- sync/apply.moon
-- Fusionne base/config.moon + devices/<hostname>/config.moon → fichier de sortie.
-- Usage : luajit apply.lua --base <chemin> [--device <chemin>] [--output <chemin>]
--                          [--hostname <nom>] [--reload]

serializer = require "webui.serializer"

-- Fusion récursive identique à src/config.moon
is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  return (next(t) == nil) if n == 0
  for i = 1, n
    return false if t[i] == nil
  true

clone = (v) ->
  return v unless type(v) == "table"
  out = {}
  for k, item in pairs v
    out[k] = clone item
  out

merge_into = (dst, src) ->
  return dst unless type(src) == "table"
  for k, v in pairs src
    if type(v) == "table" and type(dst[k]) == "table" and not is_array(v)
      merge_into dst[k], v
    else
      dst[k] = clone v
  dst

parse_args = (args) ->
  result = {
    base: nil, device: nil
    output: "/etc/custos/config.moon"
    hostname: nil, reload: false
  }
  i = 1
  while i <= #args
    a = args[i]
    if a == "--base"
      result.base = args[i + 1]
      i += 2
    elseif a == "--device"
      result.device = args[i + 1]
      i += 2
    elseif a == "--output"
      result.output = args[i + 1]
      i += 2
    elseif a == "--hostname"
      result.hostname = args[i + 1]
      i += 2
    elseif a == "--reload"
      result.reload = true
      i += 1
    else
      i += 1
  result

opts = parse_args arg

unless opts.base
  io.stderr\write "apply: --base <chemin> requis\n"
  os.exit 1

hostname = opts.hostname
unless hostname
  fh = io.popen "uname -n"
  hostname = fh\read "*l"
  fh\close!

-- Config de base (obligatoire)
base_cfg, err = serializer.read_config opts.base
unless base_cfg
  io.stderr\write "apply: config de base introuvable #{opts.base}: #{tostring err}\n"
  os.exit 1

-- Chemin de la config device (déduit depuis base si non fourni)
device_path = opts.device
unless device_path
  base_dir = opts.base\match "^(.+)/base/config%.moon$"
  device_path = "#{base_dir}/devices/#{hostname}/config.moon" if base_dir

-- Config device (optionnel — absence normale)
device_cfg = nil
if device_path
  device_cfg, dev_err = serializer.read_config device_path
  if not device_cfg and dev_err and not tostring(dev_err)\match "No such file"
    io.stderr\write "apply: avertissement #{device_path}: #{tostring dev_err}\n"

-- Fusion base + device
merged = clone base_cfg
merge_into merged, device_cfg if device_cfg

-- Écriture atomique
ok, write_err = serializer.write_config merged, opts.output
unless ok
  io.stderr\write "apply: écriture échouée #{opts.output}: #{tostring write_err}\n"
  os.exit 1

-- Rechargement optionnel
if opts.reload
  ret = os.execute "pkill -SIGHUP -f 'luajit.*main' 2>/dev/null"
  io.stderr\write "apply: SIGHUP non envoyé (service inactif ?)\n" if ret ~= 0

io.stdout\write "apply: #{opts.output} mis à jour\n"
