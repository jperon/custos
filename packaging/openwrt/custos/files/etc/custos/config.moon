-- /etc/custos/config.moon — configuration minimale CustosVirginum
-- Seules les valeurs qui diffèrent des défauts ou sont propres au déploiement
-- ont besoin d'être renseignées ici. Voir doc/CONFIG.md pour la référence complète.

{
  -- auth: {
  --   bridge_ifname: "br-lan"    -- interface bridge locale (défaut : "br0")
  --   cert: "/etc/custos/certs/auth.crt"  -- optionnel : cert TLS statique
  --   key:  "/etc/custos/keys/auth.key"   -- optionnel : clé TLS statique
  -- }

  filter: {
    -- Règles de filtrage propres au déploiement.
    -- Sans règle, le filtre tombe sur la politique par défaut (allow).
    -- Les règles intégrées (anti-DoH, sondes captives, SafeSearch) sont
    -- toujours actives ; elles sont injectées avant celles-ci.
    rules: {}
  }
}
