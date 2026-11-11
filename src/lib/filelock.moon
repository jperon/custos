-- src/lib/filelock.moon
-- Verrou de fichier inter-processus (flock) pour sérialiser les cycles
-- lecture-modification-écriture de fichiers partagés entre enfants AUTH forké
-- (fichier de sessions, fichier de secrets). Chaque enfant ouvre le fichier de
-- verrou APRÈS le fork : un descripteur hérité partagerait le verrou et ne
-- protégerait rien.
--
-- Le verrou est relâché et le descripteur fermé dans tous les cas (succès,
-- erreur de fn, erreur de flock). L'erreur éventuelle de fn est relancée après
-- libération, pour ne pas laisser le verrou tenu par un pcall conteneur.

{ :ffi } = require "ffi_defs"

LOCK_EX = 2
LOCK_UN = 8
O_RDWR  = 0x0002
O_CREAT = 0x0040

pcall ffi.cdef, [[ int flock(int fd, int operation); ]]

--- Empaquette des valeurs de retour en comptant les trous (`nil` en tête).
-- `{...}` ne garantit pas `#t` dès qu'un `nil` précède une valeur : un fn
-- retournant `nil, "erreur"` perdrait son message. On fige donc le nombre
-- exact de retours via `select "#"`, puis on déballe avec cette borne.
-- @tparam ... Valeurs à empaqueter
-- @treturn table `{ n: <nombre>, [1..n]: <valeurs> }`
pack = (...) ->
  t = { n: select "#", ... }
  for i = 1, t.n
    t[i] = select i, ...
  t

--- Exécute fn en tenant un verrou exclusif sur lock_path.
-- @tparam string   lock_path Chemin du fichier de verrou (créé si absent)
-- @tparam function fn        Fonction à exécuter sous verrou
-- @treturn ... Valeurs de retour de fn ; relance son erreur si elle lève
-- @raise string si l'ouverture du verrou échoue
with_lock = (lock_path, fn) ->
  error "with_lock: lock_path requis" unless lock_path
  -- Le mode est un argument variadique : LuaJIT passe un number Lua en double,
  -- d'où le cast explicite vers le type attendu (sinon le fichier naît en 0000).
  fd = ffi.C.open lock_path, O_RDWR + O_CREAT, ffi.cast "unsigned int", 0x180
  error "with_lock: impossible d'ouvrir le verrou #{lock_path}" if fd < 0

  if ffi.C.flock(fd, LOCK_EX) != 0
    -- Verrou non obtenu (FS sans flock ?) : on ferme et on poursuit sans
    -- verrou plutôt que de bloquer définitivement le portail. Les écritures
    -- restent atomiques (temp + rename), seul le risque de perte concurrente
    -- subsiste — comportement d'avant ce correctif.
    ffi.C.close fd
    return fn!

  results = pack pcall fn
  ffi.C.flock fd, LOCK_UN
  ffi.C.close fd
  error results[2] unless results[1]
  unpack results, 2, results.n

{ :with_lock }
