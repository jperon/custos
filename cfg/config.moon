-- Exemple config.moon
-- Peut être chargé via CUSTOS_CONFIG_PATH=./cfg/config.moon

{
  runtime: {
    log_level: "INFO"
    benchmark: false
  }

  nfqueue: {
    questions: "0-1"
    responses: "4"
    captive: "20"
    reject: "10-11"
    auth: "5"
    sni_log: "6"
  }

  dns: {
    port: 53
    ttl_grace: {
      grace: 600
      min: 60
      max: 2592000
    }
  }

  nft: {
    family: "bridge"
    family6: "bridge"
    table: "dns-filter-bridge"
    set_ip4: "ip4_allowed"
    set_ip6: "ip6_allowed"
    set_mac4: "mac4_allowed"
    set_mac6: "mac6_allowed"
    ip_timeout: "2m"
    add_retry_count: 6
    add_backoff_ms: {20, 50, 100, 200, 400, 800}
    add_failure_policy: "fail-closed"
    ack_timeout_ms: 150
    extra_rules: {}
  }

  ipc: {
    pending_ttl: 5
    match_retry: {
      enabled: true
      count: 5
      sleep_ms: 20
    }
  }

  clients: {
    expiry: 300
  }

  mac_learner: {
    query_sock: "/var/run/custos/mac_query.sock"
    learn_msg_size: 22
    entry_ttl: 300
  }

  auth: {
    host: "::"
    port: 33443
    captive_port: 33080
    cert: "/etc/custos/certs/auth.crt"
    key: "/etc/custos/keys/auth.key"
    secrets: "/etc/custos/secrets"
    session_ttl: 0
    sessions_file: "/var/run/custos/sessions.lua"
    heartbeat_interval: 30
    idle_timeout: 120
    register_rate_limit: 3
    register_rate_window: 300
    bridge_ifname: "br0"
    -- redirect_url: "https://portal.example.com/"
    sni_verdict: {
      enabled: true
      mode: "strict-443"
      protocols: "both"
      nft_failure_policy: "fail-closed"
    }
  }

  doh: {
    enabled: true
    port: 8443
    upstream_ipv4: "1.1.1.3"
    upstream_ipv6: "2606:4700:4700::1113"
    upstream_port: 53
    upstream_timeout_ms: 2000
    prefer_ipv6: true
  }

  events: {
    dir: "/tmp/custos/events"
    max_age_hours: 168
    min_free_pct: 30
  }

  filter: {
    domainlists_dir: "/etc/custos/lists"
    custom_lists_dir: "/etc/custos/lists/custom"
    allow_localnets: true

    -- ancien ip_whitelist / dest_whitelist YAML
    dest_whitelist: {
      "10.35.1.1"
      "192.168.100.0/24"
      "fd00::1"
      "2001:db8::/48"
    }

    -- utilisé pour le fallback auto si rules est vide
    allowed_domains: { "local", "lan", "home.arpa" }

    nets: {
      lan: {
        "192.168.0.0/16"
        "10.0.0.0/8"
        "172.16.0.0/12"
      }
      private_ipv6: {
        "fd00::/8"
      }
    }

    macs: {
      trusted: {
        "aa:bb:cc:dd:ee:ff"
        "11:22:33:44:55:66"
      }
      iot_devices: {
        "00:1a:2b:3c:4d:5e"
      }
    }

    times: {
      business_hours: {"08:00", "18:00"}
      after_hours: {"18:00", "08:00"}
    }

    -- clé conservée pour les conditions from_vlanlist/from_vlanlists
    vlans: {
      management: {10, 20}
      guests: {100, 101}
    }

    sources: {
      toulouse_threats: {
        url: "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
        format: "toulouse"
        categories: {"ads", "malware", "phishing"}
        subdir: "toulouse"
      }
      ads_tracking_combined: {
        urls: {
          "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
          "https://oisd.nl/domains"
        }
        format: "simple"
        output: "/etc/custos/lists/ads_tracking.bin"
      }
      my_custom_list: {
        file: "/etc/custos/lists/custom/my_list.txt"
        format: "simple"
        output: "/etc/custos/lists/custom/my_list.bin"
      }
      captive_detect: {
        file: "/etc/custos/lists/custom/captive_detect.txt"
        format: "simple"
        output: "/etc/custos/lists/captive_detect.bin"
      }
    }

    users: {
      alice: "alice@example.com"
      bob: "bob@example.com"
    }

    rules: {
      {
        description: "Détection de portail captif (systèmes d'exploitation courants)"
        actions: {"allow"}
        conditions: {
          { to_domains: {
            "connectivitycheck.gstatic.com"
            "connectivitycheck.android.com"
            "captive.apple.com"
            "www.msftconnecttest.com"
            "detectportal.firefox.com"
            "networkcheck.kde.org"
          } }
        }
      }
      {
        description: "Blocage des catégories de menaces connues"
        actions: {"deny"}
        conditions: {
          { to_domainlists: {
            "toulouse/malware"
            "toulouse/phishing"
            "toulouse/gambling"
            "toulouse/adult"
            "toulouse/publicite"
          } }
          { from_netlists: {"lan"} }
        }
      }
      {
        description: "Infrastructure réseau locale et privée toujours autorisée"
        actions: {"allow"}
        conditions: {
          { to_domains: {"local", "lan", "home.arpa"} }
          { from_netlist: "lan" }
        }
      }
      {
        description: "Outils de développement et services essentiels"
        actions: {"allow"}
        conditions: {
          { to_domains: {"github.com", "gitlab.com", "npmjs.org", "pypi.org", "debian.org"} }
          { from_maclist: "trusted" }
        }
      }
      {
        description: "Accès auth-required pour newuser"
        actions: {"allow"}
        conditions: {
          { from_user: "newuser" }
          { to_domain: "auth-required.test" }
        }
      }
      {
        description: "Accès auth-required pour testuser"
        actions: {"allow"}
        conditions: {
          { from_user: "testuser" }
          { to_domain: "auth-required.test" }
        }
      }
      {
        description: "auth-required bloqué sans authentification"
        actions: {"deny"}
        conditions: {
          { to_domain: "auth-required.test" }
        }
      }
      {
        description: "Blocage explicite de facebook.com"
        actions: {"deny"}
        conditions: {
          { to_domain: "facebook.com" }
        }
      }
      {
        description: "Autorisation DNS sondes captives sans ouverture pare-feu"
        actions: {"dnsonly"}
        conditions: {
          { to_domainlist: "custom/captive_detect" }
        }
      }
      {
        description: "Autorisation trafic VLAN 100"
        actions: {"allow"}
        conditions: {
          { from_vlan: 100 }
        }
      }
      {
        description: "Blocage VLANs de test"
        actions: {"deny"}
        conditions: {
          { from_vlans: {300, 301, 302} }
        }
      }
      {
        description: "Accès restreint groupe VLAN guests"
        actions: {"allow"}
        conditions: {
          { from_vlanlist: "guests" }
          { to_domain: "portal.example.com" }
        }
      }
      {
        description: "Autorisation par défaut"
        actions: {"allow"}
      }
    }

    decision: {
      first_match_wins: true
      continue_to_next_rule: false
    }
  }
}
