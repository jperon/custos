-- src/webui/audit.moon
-- Journal d'audit des modifications faites depuis l'interface d'admin
-- (src/webui/). Une requête mutante réussie ou échouée émet exactement une
-- ligne INFO ; une tentative refusée (non admin, validation) émet un WARN.
--
-- Principe : on journalise QUI a touché QUOI, jamais la valeur. Les champs
-- d'objet sont donc limités à une liste blanche de métadonnées (nom de
-- section, identifiant de règle, nom de liste/appareil…). Aucune valeur de
-- configuration, aucun secret (auth.secrets/auth.key/doh.key), aucun contenu
-- de liste ne doit transiter par ce module.
--
-- La webui s'exécute dans l'enfant AUTH-conn : le worker AUTH a déjà posé le
-- préfixe `auth_` (auth/worker.moon:30), donc les actions sont émises
-- `auth_webui_*`. C'est voulu et cohérent avec les autres lignes AUTH ; le
-- rate-limiting retire ce préfixe avant de consulter RL_NEVER_LIMIT/RL_CONFIG
-- (log.moon, `_rl_never_limited` et `_rl_resolve_cfg`). Ce module ne touche
-- jamais à l'état global du journal au chargement.

{ :log_info, :log_warn } = require "log"

-- Champs d'objet autorisés : uniquement des métadonnées (noms/identifiants).
-- Tout autre champ passé par un handler est ignoré, ce qui protège d'une
-- fuite accidentelle de valeur (mot de passe, clé, contenu de liste).
OBJECT_KEYS = {
  "section": true
  "rule_id": true
  "list":    true
  "name":    true
  "new":     true
  "mac":     true
  "dir":     true
  "rules":   true
  "enabled": true
  "pid":     true
}

-- Longueur maximale d'un code d'erreur/raison. Ce sont des codes courts
-- (`write_config`, `forbidden`…), jamais un message brut.
MAX_CODE_LEN = 48

-- Longueur maximale d'une valeur d'objet (nom, MAC, section…). Ces valeurs
-- viennent du formulaire : on les borne pour qu'un POST ne puisse pas gonfler
-- la ligne de journal ni noyer logread.
MAX_OBJECT_LEN = 64

--- Assainit une valeur d'objet contrôlée par l'utilisateur.
-- `format_line` (log.moon) ne cite que les valeurs contenant un espace et
-- n'échappe ni `=`, ni `"`, ni les sauts de ligne : sans ce filtre, un nom
-- `x ok=1 user=admin` injecterait une fausse paire, et un `\n` une fausse
-- ligne. Contrôles, espaces, `=` et `"` deviennent `_` ; la valeur est bornée
-- à MAX_OBJECT_LEN. Les nombres (rule_id, pid, enabled, rules) passent tels
-- quels.
-- @tparam any v Valeur proposée
-- @treturn any Nombre inchangé, ou chaîne assainie/bornée
sanitize_object = (v) ->
  return v if type(v) == "number"
  out = tostring v
  out = out\gsub "[%c%s=\"]", "_"
  out\sub 1, MAX_OBJECT_LEN

--- Réduit une raison/erreur à un code court et sûr pour le journal.
-- Les caractères hors [A-Za-z0-9_.-] deviennent `_` : ni espace, ni saut de
-- ligne, ni valeur brute potentiellement sensible.
-- @tparam string|nil s Texte à assainir
-- @treturn string Code court (jamais nil)
short_code = (s) ->
  out = tostring s or "unknown"
  out = out\gsub "[^%w_%-%.]", "_"
  out\sub 1, MAX_CODE_LEN

--- Champs d'identité de l'appelant (jamais nil dans le journal).
-- @tparam table|nil req Requête webui (req.admin_user, req.peer_ip)
-- @treturn table `{ user, peer }`
actor = (req) ->
  {
    user: (req and req.admin_user) or "?"
    peer: (req and req.peer_ip) or "unknown"
  }

--- Filtre les champs d'objet par la liste blanche OBJECT_KEYS et les assainit.
-- @tparam table|nil fields Champs proposés par le handler
-- @treturn table Champs autorisés, valeurs nil retirées
object_fields = (fields) ->
  out = {}
  if fields
    for k, v in pairs fields
      out[k] = sanitize_object v if OBJECT_KEYS[k] and v != nil
  out

emit_change = (req, action, fields, ok, err) ->
  out = actor req
  out.action = action
  out.ok = ok and 1 or 0
  for k, v in pairs object_fields fields
    out[k] = v
  out.err = short_code err if not ok and err
  log_info -> out

--- Journalise une modification réussie (INFO, une seule ligne).
-- @tparam table req Requête webui (user/peer)
-- @tparam string action Action de base `webui_*` (émise `auth_webui_*` dans
--   le worker AUTH ; jamais limitée)
-- @tparam table|nil fields Métadonnées de l'objet touché
-- @treturn nil
change = (req, action, fields) ->
  emit_change req, action, fields, true
  nil

--- Journalise une modification tentée mais échouée (INFO ok=0).
-- @tparam table req Requête webui
-- @tparam string action Action de base `webui_*`
-- @tparam table|nil fields Métadonnées de l'objet touché
-- @tparam string err Code d'erreur court (jamais un message brut)
-- @treturn nil
fail = (req, action, fields, err) ->
  emit_change req, action, fields, false, err
  nil

--- Journalise une tentative refusée (WARN, limitée par peer+reason).
-- Couvre non-admin (routeur), validation et conflits de handler. Dans le
-- worker AUTH, l'action émise est `auth_webui_change_refused` ; la règle
-- RL_CONFIG est retrouvée après retrait du préfixe.
-- @tparam table req Requête webui
-- @tparam string reason Code de refus (`forbidden`, `invalid_name`…)
-- @tparam table|nil fields Métadonnées éventuelles (objet visé)
-- @treturn nil
refused = (req, reason, fields) ->
  out = actor req
  out.action = "webui_change_refused"
  out.reason = short_code reason
  out.ok = 0
  for k, v in pairs object_fields fields
    out[k] = v
  log_warn -> out
  nil

{
  :change, :fail, :refused
  :short_code, :actor, :object_fields, :sanitize_object
  :OBJECT_KEYS, :MAX_CODE_LEN, :MAX_OBJECT_LEN
}
