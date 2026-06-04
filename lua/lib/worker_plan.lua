local plan_optional_workers
plan_optional_workers = function(cfg, is_lowmem)
  local nfq = cfg.nfqueue or { }
  local doh = cfg.doh or { }
  return {
    sip = not not nfq.sip,
    tls = not not (nfq.sni and not is_lowmem),
    doh = not not (doh.enabled and not is_lowmem)
  }
end
return {
  plan_optional_workers = plan_optional_workers
}
