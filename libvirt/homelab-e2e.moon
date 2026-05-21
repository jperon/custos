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
  }

  dns: {
    port: 53
    -- TTL courts pour que les sets nftables expirent vite en test.
    ttl_grace: { grace: 60, min: 30, max: 300 }
  }

  nft: {
    family:   "bridge"
    family6:  "bridge"
    table:    "dns-filter-bridge"
    set_ip4:  "ip4_allowed"
    set_ip6:  "ip6_allowed"
    set_mac4: "mac4_allowed"
    set_mac6: "mac6_allowed"
    ip_timeout: "2m"
  }

  auth: {
    enabled:       true
    port:          33443
    redirect_url:  "https://custos.lan:33443/auth"
    cert:          "/etc/custos/cert.pem"
    key:           "/etc/custos/key.pem"
    sessions_file: "/etc/custos/sessions.lua"
    users: {
      alice: "motdepasse123"
    }
  }

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

      -- R3 : depuis homelab, autoriser tout SAUF blocked.lan (teste condition `not`)
      --   • blocked.lan ne matche pas cette règle → tombe sur R5 default_deny
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

      -- R4 : forcer l'authentification si pas de session active
      {
        rule_id:     "challenge_auth"
        description: "Auth requise si pas de session"
        actions:     {"challenge"}
      }

      -- R5 : refus par défaut
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
