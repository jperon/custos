-- Runtime source-of-truth for Custos.
-- Partial overrides only: absent keys keep built-in defaults from src/config.moon.

return {
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
    forced_ttl: 60
    ttl_grace: {
      grace: 600
      min: 60
      max: 2592000
    }
  }

  nft: {
    ip_timeout: "2m"
    add_failure_policy: "fail-closed"
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
    entry_ttl: 300
  }

  auth: {
    sessions_file: "/tmp/custos/sessions.lua"
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
    dest_whitelist: {}
    decision: {
      first_match_wins: true
      continue_to_next_rule: false
    }
  }
}
