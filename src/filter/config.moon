-- src/filter/config.moon
-- Configuration du filtre d'autorisations.
-- Ce fichier remplace la liste plate ALLOWED_DOMAINS de src/config.moon.
-- Il est rechargé à chaud via SIGHUP (filter.reload()).
--
-- ── Format ────────────────────────────────────────────────────────
-- domains  : table nom → chemin vers fichier .bin (compilé par filter/convert)
--            ou .domains (texte, chargé à la volée au démarrage).
-- nets     : table nom → liste de CIDR IPv4/IPv6
-- times    : table nom → {"HH:MM", "HH:MM"} (début, fin)
-- rules    : tableau ordonné de règles (premier verdict gagnant)
--
-- ── Conditions disponibles ────────────────────────────────────────
-- to_domain        : correspondance exacte/suffixe sur un domaine
-- to_domains       : correspondance sur plusieurs domaines
-- to_domainlist    : appartenance à une liste binaire (nom depuis domains{})
-- to_domainlists   : appartenance à plusieurs listes
-- from_mac         : adresse MAC source
-- from_net         : adresse IP source dans un CIDR
-- from_netlist     : adresse IP source dans une netlist nommée
-- from_netlists    : adresse IP source dans l'une de plusieurs netlists
-- in_time          : dans une fenêtre horaire nommée (depuis times{})
-- in_times         : dans l'une de plusieurs fenêtres horaires
-- stolen_computer  : MAC source dans une liste noire
-- from_user        : utilisateur authentifié (squelette — future)
--
-- ── Actions disponibles ───────────────────────────────────────────
-- allow   : autoriser
-- deny    : bloquer
-- mail    : notification e-mail (squelette — future)

{
  -- Listes de domaines précompilées (filter/convert.moon)
  -- Commenter les entrées pour passer en mode liste plate (rules ci-dessous).
  domains: {
    -- maj:    "/etc/custos/lists/MaJ.bin"
    -- ouvert: "/etc/custos/lists/Ouvert.bin"
  }

  -- Netlists : sous-réseaux CIDR nommés
  nets: {
    lan: { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" }
  }

  -- Fenêtres horaires (format "HH:MM")
  times: {
    -- business: { "08:00", "18:00" }
  }

  -- Sources pour filter/updater.moon : téléchargement et compilation automatique
  -- des listes de blocage. Exécuter : luajit lua/filter/updater.lua [--pid /run/custos.pid]
  --
  -- formats : "simple" (1 domaine/ligne), "hosts" (0.0.0.0 domain), "adblock" (||domain^)
  sources: {
    -- ads: {
    --   urls:   { "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }
    --   format: "hosts"
    --   output: "/etc/custos/lists/ads.bin"
    -- }
    -- tracking: {
    --   urls:   { "https://oisd.nl/domains" }
    --   format: "simple"
    --   output: "/etc/custos/lists/tracking.bin"
    -- }
  }

  -- Règles ordonnées : premier verdict gagnant.
  -- Les règles remplacent intégralement ALLOWED_DOMAINS.
  rules: {
    {
      description: "Infrastructure réseau toujours autorisée"
      conditions:  { to_domains: { "local", "lan", "home.arpa" } }
      actions:     { "allow" }
    }
    {
      description: "Outils de développement"
      conditions:  {
        to_domains: {
          "github.com"
          "gitlab.com"
          "npmjs.org"
          "pypi.org"
          "debian.org"
          "ubuntu.com"
          "archlinux.org"
          "cloudflare.com"
          "fastly.com"
          "akamaiedge.net"
          "example.com"
        }
      }
      actions: { "allow" }
    }
    {
      description: "Refus par défaut"
      conditions:  {}
      actions:     { "deny" }
    }
  }
}
