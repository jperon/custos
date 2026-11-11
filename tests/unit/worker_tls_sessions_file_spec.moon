-- tests/unit/worker_tls_sessions_file_spec.moon
-- Régression : `auth_sessions_file` n'était assignée que dans run(), donc
-- locale à cette fonction ; la lecture du hot-path SNI
-- (`user: user_for_mac mac_str, ip_src_str, auth_sessions_file`) compilait en
-- lecture de globale, c.-à-d. nil. `user_for_mac` recevait alors un chemin nil :
-- load_sessions(nil) rend {}, donc aucune session n'est trouvée et le champ
-- `user` de la requête SNI reste toujours nil.
--
-- Le chemin est désormais initialisé au niveau module, avec la même valeur par
-- défaut que worker_responses (/tmp/sessions.lua), puis affiné dans run() par
-- filter.get_auth_cfg().sessions_file.

config = require "config"
worker_tls = require "worker_tls"

describe "worker_tls auth_sessions_file", ->

  it "est initialisé au niveau module depuis config.auth", ->
    expected = (config.auth and config.auth.sessions_file) or "/tmp/sessions.lua"
    assert.equals expected, worker_tls.auth_sessions_file
    assert.is_string worker_tls.auth_sessions_file
