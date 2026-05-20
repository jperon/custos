-- libvirt/homelab-test.moon — config minimale custos pour valider la chaîne
-- servus → custos → via. Déployée sur /etc/custos/config.moon par homelab.sh.

{
  runtime: {
    log_level: "INFO"
  }

  nfqueue: {
    questions: "0-1"
    responses: "4"
    captive: "20"
    reject: "10-11"
    auth: "5"
  }

  dns: {
    port: 53
  }

  nft: {
    family: "bridge"
    family6: "bridge"
    table: "dns-filter-bridge"
    set_ip4: "ip4_allowed"
    set_ip6: "ip6_allowed"
    set_mac4: "mac4_allowed"
    set_mac6: "mac6_allowed"
  }

  filter: {
    allow_localnets: true
    allowed_domains: {"lan"}

    nets: {
      homelab: {"10.42.0.0/24"}
    }

    rules: {
      {
        description: "Homelab — résolution interne autorisée"
        actions: {"allow"}
        conditions: {
          to_domains: {"via.lan", "site-a.lan"}
          from_netlist: "homelab"
        }
      }
      {
        description: "Homelab — blocage explicite site-b"
        actions: {"deny"}
        conditions: {
          to_domain: "site-b.lan"
        }
      }
      {
        description: "Refus par défaut"
        actions: {"deny"}
      }
    }

    decision: {
      first_match_wins: true
    }
  }
}
