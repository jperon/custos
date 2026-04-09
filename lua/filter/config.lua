return {
  domains = { },
  nets = {
    lan = {
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    }
  },
  times = { },
  sources = { },
  rules = {
    {
      description = "Infrastructure réseau toujours autorisée",
      conditions = {
        to_domains = {
          "local",
          "lan",
          "home.arpa"
        }
      },
      actions = {
        "allow"
      }
    },
    {
      description = "Outils de développement",
      conditions = {
        to_domains = {
          "github.com",
          "gitlab.com",
          "npmjs.org",
          "pypi.org",
          "debian.org",
          "ubuntu.com",
          "archlinux.org",
          "cloudflare.com",
          "fastly.com",
          "akamaiedge.net",
          "example.com"
        }
      },
      actions = {
        "allow"
      }
    },
    {
      description = "Refus par défaut",
      conditions = { },
      actions = {
        "deny"
      }
    }
  }
}
