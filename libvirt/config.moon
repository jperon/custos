# libvirt/config.moon — configuration custos pour l'environnement E2E libvirt.
# Déployée sur /etc/custos/config.moon par `make test-e2e`.

auth:
  idle_timeout: 10
  heartbeat_interval: 5
  register_rate_limit: 100
  register_rate_window: 60
  secrets: /etc/custos/secrets
  bridge_ifname: br-lan
  captive_ip4: 10.99.0.254

nets:
  lan:
    - 10.99.0.0/24

rules:
  # Autorise explicitement le domaine allowed (+ sous-domaines)
  - description: E2E — domaine autorisé
    actions: [allow]
    conditions:
      to_domains:
        - allowed.test
        - mail.allowed.test

  # Bloque explicitement les domaines de test
  - description: E2E — domaine bloqué (HTTP, déclenche captive captive)
    actions: [deny]
    conditions:
      to_domain: blocked.test

  - description: E2E — tracker (HTTPS, déclenche reject)
    actions: [deny]
    conditions:
      to_domain: tracker.test

  # Refus par défaut : les domaines inconnus (ex. nonexistent.invalid) sont
  # bloqués → NXDOMAIN + EDE Filtered, ce que la suite E2E vérifie.
  - description: E2E — refus par défaut
    actions: [deny]
