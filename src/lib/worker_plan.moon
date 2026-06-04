-- src/lib/worker_plan.moon
-- Détermine quels workers optionnels doivent être lancés selon la config
-- et le mode RAM faible. Fonction pure, sans effet de bord — testable en isolation.
--
-- Les workers obligatoires (mac-lrn, events, arp, auth-q, auth, nft, resp-qN,
-- dns-qN, cap-qN, rej-qN) sont toujours présents et ne dépendent pas de ce module.
-- Seuls les workers optionnels (sip, tls, doh) sont pilotés ici.

--- Renvoie un tableau indiquant quels workers optionnels seraient lancés.
-- @tparam table cfg  Table de configuration (champs nfqueue, doh)
-- @tparam boolean is_lowmem  true si le mode RAM faible est actif
-- @treturn table  Clés booléennes : { sip, tls, doh }
plan_optional_workers = (cfg, is_lowmem) ->
  nfq = cfg.nfqueue or {}
  doh = cfg.doh or {}
  {
    sip: not not nfq.sip
    tls: not not (nfq.sni and not is_lowmem)
    doh: not not (doh.enabled and not is_lowmem)
  }

{ :plan_optional_workers }
