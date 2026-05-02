-- src/auth/cert_generator.moon
-- Wrapper pour binaire px5g (PX5G X.509 Certificate Generator using WolfSSL)
-- Génère des clés RSA et certificats auto-signés via io.popen.
-- Aucun fallback openssl : px5g est une dépendance obligatoire.

{ :log_debug, :log_warn, :log_error } = require "log"

--- Génère une clé RSA via px5g.
-- @tparam number bits Taille de la clé (ex: 2048, 4096)
-- @treturn string|nil Clé PEM, ou nil en cas d'erreur
-- @treturn boolean true si succès, false sinon
-- @treturn string Message d'erreur si échec
generate_rsa_key = (bits = 2048) ->
  bits = tonumber(bits) or 2048
  cmd = "px5g rsakey #{bits}"
  
  handle = io.popen cmd
  unless handle
    err = "Failed to spawn px5g rsakey"
    log_error { action: "cert_gen_spawn_failed", cmd: cmd, err: err }
    return nil, false, err
  
  key_pem, read_err = handle\read "*a"
  close_ok = handle\close!
  
  unless close_ok
    err = "px5g rsakey exited with error (exit code non-zero)"
    log_warn { action: "cert_gen_rsakey_failed", bits: bits, err: err }
    return nil, false, err
  
  unless key_pem and #key_pem > 0
    err = "px5g rsakey produced empty output"
    log_warn { action: "cert_gen_rsakey_empty", bits: bits }
    return nil, false, err
  
  -- Vérifier que c'est du PEM valide (BEGIN/END)
  unless key_pem\match "BEGIN.*PRIVATE KEY"
    err = "px5g rsakey output is not valid PEM"
    log_warn { action: "cert_gen_rsakey_invalid_pem" }
    return nil, false, err
  
  log_debug { action: "cert_gen_rsakey_success", bits: bits, size: #key_pem }
  key_pem, true, nil

--- Génère un certificat auto-signé complet via px5g.
-- Utilise la syntaxe correcte : px5g selfsigned -newkey ec -keyout key.pem -out cert.pem -subj "/CN=..."
-- Crée deux fichiers temporaires (clé et certificat) et les rellit.
-- @tparam string cn Common Name (ex: "example.com")
-- @tparam table sans Subject Alternative Names list (ex: {"example.com", "*.example.com"})
-- @tparam number days Validité en jours (par défaut 3650) - NOTE: px5g peut ne pas supporter cet argument
-- @treturn string|nil Clé privée PEM, ou nil en cas d'erreur
-- @treturn string|nil Certificat PEM, ou nil en cas d'erreur
-- @treturn boolean true si succès, false sinon
-- @treturn string Message d'erreur si échec
generate_self_signed = (cn, sans = {}, days = 3650) ->
  unless cn and #cn > 0
    err = "CN (Common Name) is empty or nil"
    log_warn { action: "cert_gen_selfsigned_nocn", err: err }
    return nil, nil, false, err
  
  days = tonumber(days) or 3650
  
  -- Créer des fichiers temporaires pour px5g (il écrit les fichiers, ne produit pas stdout)
  key_file = "/tmp/px5g_key_#{os.time!}_#{math.random(1000000)}.pem"
  cert_file = "/tmp/px5g_cert_#{os.time!}_#{math.random(1000000)}.pem"
  
  -- Construire la commande px5g avec les bons paramètres
  -- Syntaxe: px5g selfsigned -newkey ec -keyout key.pem -out cert.pem -subj "/CN=hostname"
  cmd = "px5g selfsigned -newkey ec -keyout #{key_file} -out #{cert_file} -subj \"/CN=#{cn}\" 2>/dev/null"
  
  log_debug { action: "cert_gen_selfsigned_cmd", cn: cn, cmd: cmd }
  
  -- Exécuter px5g
  log_debug { action: "cert_gen_px5g_executing", cn: cn, key_file: key_file, cert_file: cert_file }
  exit_code = os.execute cmd
  log_debug { action: "cert_gen_px5g_done", cn: cn, exit_code: exit_code }
  unless exit_code == 0 or exit_code == true  -- os.execute returns true on success in Lua 5.1, 0 in 5.2+
    err = "px5g selfsigned exited with error code #{exit_code}"
    log_warn { action: "cert_gen_selfsigned_failed", cn: cn, err: err }
    -- Nettoyer les fichiers au cas où ils existent
    os.remove key_file
    os.remove cert_file
    return nil, nil, false, err
  
  -- Lire la clé privée du fichier
  log_debug { action: "cert_gen_key_reading", cn: cn, key_file: key_file }
  key_fh = io.open key_file, "r"
  unless key_fh
    err = "Cannot read generated key file: #{key_file}"
    log_warn { action: "cert_gen_key_read_failed", cn: cn, err: err }
    os.remove cert_file
    return nil, nil, false, err
  
  key_pem = key_fh\read "*a"
  key_fh\close!
  
  unless key_pem and #key_pem > 0
    err = "px5g generated empty key file"
    log_warn { action: "cert_gen_key_empty", cn: cn }
    os.remove cert_file
    return nil, nil, false, err
  
  log_debug { action: "cert_gen_key_read_ok", cn: cn, key_size: #key_pem }
  
  -- Lire le certificat du fichier
  log_debug { action: "cert_gen_cert_reading", cn: cn, cert_file: cert_file }
  cert_fh = io.open cert_file, "r"
  unless cert_fh
    err = "Cannot read generated cert file: #{cert_file}"
    log_warn { action: "cert_gen_cert_read_failed", cn: cn, err: err }
    return nil, nil, false, err
  
  cert_pem = cert_fh\read "*a"
  cert_fh\close!
  
  unless cert_pem and #cert_pem > 0
    err = "px5g generated empty cert file"
    log_warn { action: "cert_gen_cert_empty", cn: cn }
    return nil, nil, false, err
  
  -- Nettoyer les fichiers temporaires (les PEM sont maintenant en mémoire)
  os.remove key_file
  os.remove cert_file
  
  log_debug { 
    action: "cert_gen_selfsigned_success"
    cn: cn
    sans_count: #sans
    key_size: #key_pem
    cert_size: #cert_pem
  }
  key_pem, cert_pem, true, nil

{
  :generate_rsa_key
  :generate_self_signed
}
