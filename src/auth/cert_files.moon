-- src/auth/cert_files.moon
-- Écriture atomique des paires clé/certificat du portail AUTH.
--
-- Deux enfants AUTH-conn peuvent générer le certificat du même nom en même
-- temps (première connexion) : sans sérialisation, l'un pouvait remplacer la
-- clé pendant que l'autre écrivait le certificat, et le contexte WolfSSL
-- chargé ensuite pouvait contenir une paire dépareillée.
--
-- Chaque fichier est écrit dans un temporaire propre au PID puis renommé
-- (`os.rename`, atomique sur un même système de fichiers) ; la paire entière
-- est en outre écrite ET relue sous un verrou flock commun (`lib.filelock`) :
-- le perdant de la course réutilise la paire complète du gagnant au lieu de
-- l'écraser, et l'appelant ne reçoit jamais un contenu partiel.

ffi = require "ffi"
{ :log_debug } = require "log"
{ :with_lock } = require "lib.filelock"

pcall ffi.cdef, "int getpid(void);"

-- Compteur local en plus du PID : deux écritures du même processus (rsakey,
-- selfsigned, plusieurs noms) ne partagent jamais le même temporaire.
_tmp_seq = 0

tmp_path = (path) ->
  _tmp_seq += 1
  "#{path}.tmp.#{tonumber ffi.C.getpid!}_#{_tmp_seq}"

--- Lit un fichier entier.
-- @tparam string path Chemin
-- @treturn string|nil Contenu, ou nil si illisible
read_file = (path) ->
  fh = io.open path, "r"
  return nil unless fh
  content = fh\read "*a"
  fh\close!
  content

--- Vrai si le fichier existe et n'est pas vide.
-- @tparam string path Chemin
-- @treturn boolean
file_complete = (path) ->
  content = read_file path
  content and #content > 0

--- Écrit `content` dans `path` de façon atomique (temporaire + rename).
-- Aucun fichier partiel n'apparaît au chemin final ; en cas d'échec, le
-- temporaire est supprimé.
-- @tparam string path Destination
-- @tparam string content Contenu PEM
-- @tparam function|nil rename_fn Injection de test ; défaut os.rename
-- @treturn boolean Succès
-- @treturn string|nil Message d'erreur
write_pem_atomic = (path, content, rename_fn=os.rename) ->
  tmp = tmp_path path
  fh, err = io.open tmp, "w"
  unless fh
    return false, "Impossible d'ouvrir #{tmp} : #{err}"
  ok_w, write_err = pcall -> fh\write content
  fh\close!
  unless ok_w
    pcall os.remove, tmp
    return false, "Impossible d'écrire #{tmp} : #{write_err}"
  ok_r, rename_err = rename_fn tmp, path
  unless ok_r
    pcall os.remove, tmp
    return false, "Impossible de renommer #{tmp} → #{path} : #{rename_err}"
  true, nil

--- Matérialise la paire clé/certificat et retourne le contenu réel sur disque.
-- Sous verrou : si un autre enfant a déjà écrit une paire complète, elle est
-- réutilisée telle quelle (le perdant relit le gagnant). Sinon les deux
-- fichiers sont écrits atomiquement puis relus sous le même verrou ; aucune
-- paire dépareillée n'est donc rendue à l'appelant, et une paire complète
-- n'est plus jamais réécrite tant que ses fichiers existent.
-- @tparam string key_path Chemin de la clé
-- @tparam string cert_path Chemin du certificat
-- @tparam string key_pem Clé générée (ou en cache)
-- @tparam string cert_pem Certificat généré (ou en cache)
-- @tparam table|nil opts { rename_fn } (injection de test)
-- @treturn string Clé réellement présente sur disque
-- @treturn string Certificat réellement présent sur disque
-- @raise string si l'écriture ou la relecture échoue
materialize_pair = (key_path, cert_path, key_pem, cert_pem, opts={}) ->
  rename_fn = opts.rename_fn or os.rename
  -- Le verrou est un fichier distinct : le supprimer après coup recréerait une
  -- course (un troisième enfant recréerait un inode différent et deux verrous
  -- coexisteraient). Il reste donc dans tmp/, au même titre que les PEM.
  lock_path = "#{cert_path}.lock"
  status = nil

  with_lock lock_path, ->
    if file_complete(key_path) and file_complete(cert_path)
      status = "existing"
    else
      ok_key, err_key = write_pem_atomic key_path, key_pem, rename_fn
      unless ok_key
        error "Écriture de la clé SNI impossible (#{key_path}) : #{err_key}"
      ok_cert, err_cert = write_pem_atomic cert_path, cert_pem, rename_fn
      unless ok_cert
        -- Ne jamais laisser une clé sans certificat derrière soi : la paire
        -- incomplète serait réparée au prochain passage, mais un lecteur
        -- pourrait l'ouvrir entre-temps.
        pcall os.remove, key_path
        error "Écriture du certificat SNI impossible (#{cert_path}) : #{err_cert}"
      status = "written"

  disk_key = read_file key_path
  disk_cert = read_file cert_path
  unless disk_key and disk_cert and #disk_key > 0 and #disk_cert > 0
    error "Paire clé/certificat illisible après écriture (#{key_path})"
  log_debug -> { action: "cert_pair_materialized", key_file: key_path, status: status }
  disk_key, disk_cert

{ :write_pem_atomic, :materialize_pair, :read_file, :file_complete }
