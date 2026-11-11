-- /etc/custos/config.moon — configuration runtime de CustosVirginum
--
-- Surcharge PARTIELLE : seules les clés présentes ici remplacent les défauts de
-- src/config.moon (livrés et mis à jour avec le paquet). Ne recopiez pas les
-- défauts ici : ce fichier est un conffile, il n'est pas écrasé à la mise à
-- jour et figerait donc les valeurs de la version installée.
--
-- Référence complète : doc/CONFIG.md. Le chemin est passé au superviseur par
-- CUSTOS_CONFIG_PATH (/etc/init.d/custos) ; CUSTOS_REQUIRE_EXTERNAL_CONFIG=1
-- fait échouer le démarrage si ce fichier ne se charge pas.

{

  filter: {
    -- Le filtre fonctionne sans règle : les règles intégrées (anti-DoH, sondes
    -- de portail captif, SafeSearch) sont injectées avant celles-ci
    -- (src/config.moon DEFAULTS.filter.default_rules).
    rules: {}
  }

  -- Exemples — décommenter et adapter au déploiement :
  --
  -- auth: {
  --   bridge_ifname: "br-lan"              -- autodétecté (bridge le plus peuplé) si absent
  --   cert: "/etc/custos/certs/auth.crt"   -- sinon certificat auto-signé généré au démarrage
  --   key:  "/etc/custos/keys/auth.key"
  -- }
  --
  -- filter: {
  --   allow_localnets: true               -- réseaux locaux injectés en whitelist nft (défaut false)
  --   nets: {
  --     lan: { "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12" }
  --   }
  --   rules: {
  --     {
  --       description: "Infrastructure locale toujours autorisée"
  --       actions: {"allow"}
  --       conditions: { to_domains: {"local", "lan", "home.arpa"} }
  --     }
  --   }
  -- }
}
