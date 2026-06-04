-- Configuration CustosVirginum
-- Seuls les paramètres qui diffèrent des valeurs par défaut sont définis ici.
-- Voir doc/CONFIG.md pour la référence complète.

{
  auth: {
    cert: "/etc/custos/certs/auth.crt"
    key:  "/etc/custos/keys/auth.key"
  }

  filter: {
    -- allow_localnets est false par défaut ; à true sur un routeur domestique.
    allow_localnets: true

    nets: {
      lan: {
        "192.168.0.0/16"
        "10.0.0.0/8"
        "172.16.0.0/12"
      }
    }

    rules: {
      {
        description: "Infrastructure locale toujours autorisée"
        actions: {"allow"}
        conditions: {
          to_domains: {"local", "lan", "home.arpa"}
          from_net_list: "lan"
        }
      }

      -- Enfants : liste blanche.
      -- Ajouter les domaines autorisés dans /tmp/custos/lists/enfants_allow.txt
      -- Ajouter les utilisateurs (un par ligne) dans /tmp/custos/lists/user/enfants.txt
      {
        description: "Enfants — domaines autorisés"
        actions: {"allow"}
        conditions: { from_user_list: "enfants", to_domainlist: "enfants_allow" }
      }
      {
        description: "Enfants — tout le reste bloqué"
        actions: {"deny"}
        conditions: { from_user_list: "enfants" }
      }

      -- Adultes : liste noire.
      -- Ajouter les domaines bloqués dans /tmp/custos/lists/adultes_block.txt
      -- Ajouter les utilisateurs (un par ligne) dans /tmp/custos/lists/user/adultes.txt
      {
        description: "Adultes — domaines bloqués"
        actions: {"deny"}
        conditions: { from_user_list: "adultes", to_domainlist: "adultes_block" }
      }

      {
        description: "Autorisation par défaut"
        actions: {"allow"}
      }
    }
  }
}
