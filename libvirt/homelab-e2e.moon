-- libvirt/homelab-e2e.moon — config E2E complète pour la suite homelab_e2e.sh
-- Déployée temporairement sur /etc/custos/config.moon par homelab.sh test-e2e,
-- puis remplacée par homelab-test.moon à la fin des tests.

{
  runtime: {
    log_level: "DEBUG"
  }

  nfqueue: {
    questions: "0-1"
    responses: "4"
    captive:   "20"
    reject:    "10-11"
    auth:      "5"
    sni:       "6"
  }

  dns: {
    port: 53
    -- TTL courts pour que les sets nftables expirent vite en test.
    ttl_grace: { grace: 60, min: 30, max: 300 }
  }

  nft: {
    family:        "bridge"
    family6:       "bridge"
    table:         "dns-filter-bridge"
    set_ip4:       "ip4_allowed"
    set_ip6:       "ip6_allowed"
    set_mac4:      "mac4_allowed"
    set_mac6:      "mac6_allowed"
    ip_timeout:    "2m"
    bridge_ifname: "br-lan"
  }

  auth: {
    enabled:            true
    port:               33443
    bridge_ifname:      "br-lan"
    redirect_url:       "https://10.42.0.254:33443/auth"
    cert:               "/etc/custos/cert.pem"
    key:                "/etc/custos/key.pem"
    sessions_file:      "/etc/custos/sessions.lua"
    idle_timeout:       10
    heartbeat_interval: 3
    -- alice est admin → exerce l'interface /admin (G13)
    admin_users:        {"alice@test.lan"}
  }

  -- G14 valide la capture SNI de TOUT le trafic 443, y compris les
  -- destinations déjà autorisées par DNS → placement "integral" (avant
  -- cv_action_vmap). Le défaut produit est "residual" (cf. doc/CONFIG.md).
  sni: { placement: "integral" }

  filter: {
    allow_localnets: true

    nets: {
      homelab: {"10.42.0.0/24", "fd42:42:0:1::/64"}
      ext:     {"10.43.0.0/24", "fd42:42:0:2::/64"}
    }

    macs: {
      servus: "52:54:00:fe:03:01"
    }

    rules: {
      -- R1 : VLAN 10 → DNS seulement (teste from_vlan)
      {
        rule_id:     "vlan10_dnsonly"
        description: "VLAN 10 : DNS uniquement"
        actions:     {"dnsonly"}
        conditions:  { from_vlan: 10 }
      }

      -- R2 : sous-réseau ext (cliens, 10.43.x/fd42:2) → DNS seulement
      {
        rule_id:     "ext_dnsonly"
        description: "Sous-réseau ext : DNS uniquement"
        actions:     {"dnsonly"}
        conditions:  { from_nets: {"10.43.0.0/24", "fd42:42:0:2::/64"} }
      }

      -- R2c : redirection (type SafeSearch) — verdict allow mais réécriture de
      -- destination via cname. Placée AVANT R3 (first_match_wins) pour que
      -- redir.lan matche ici. Cible volontairement non résolvable : côté SNI,
      -- worker_tls ne peut pas confirmer que le client vise la bonne IP → block
      -- (fail-closed redirect). Côté DNS, la réponse serait réécrite en CNAME.
      {
        rule_id:     "redir_cname"
        description: "Redirection cname (test SNI redirect block)"
        actions:     {"cname", "allow"}
        cname:       "unresolvable.invalid"
        conditions:  {
          to_domain: "redir.lan"
          from_nets: {"10.42.0.0/24", "fd42:42:0:1::/64"}
        }
      }

      -- R3 : depuis homelab, autoriser tout SAUF blocked.lan (teste condition `not`)
      --   • blocked.lan ne matche pas → tombe sur R4 (from_users) puis R5 default_deny
      --   • tout autre domaine depuis homelab → allow
      {
        rule_id:     "homelab_not_blocked"
        description: "Homelab : tout sauf blocked.lan"
        actions:     {"allow"}
        conditions:  {
          not:        { to_domain: "blocked.lan" }
          from_nets:  {"10.42.0.0/24", "fd42:42:0:1::/64"}
        }
      }

      -- R4 : homelab authentifié → blocked.lan accessible (teste from_users + sets auth nft)
      --   • sans auth : from_users échoue → R5 default_deny → REFUSED
      --   • avec auth : from_users réussit → allow → NOERROR
      {
        rule_id:     "homelab_auth_blocked"
        description: "Homelab authentifié : blocked.lan accessible"
        actions:     {"allow"}
        conditions:  {
          from_users: "_any"
          from_nets:  {"10.42.0.0/24", "fd42:42:0:1::/64"}
          to_domain:  "blocked.lan"
        }
      }

      {
        rule_id:     "default_deny"
        description: "Refus par défaut"
        actions:     {"deny"}
      }
    }

    decision: {
      first_match_wins: true
    }
  }
}
