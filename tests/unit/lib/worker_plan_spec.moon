-- tests/unit/lib/worker_plan_spec.moon
-- Tests unitaires de lib.worker_plan : sélection des workers optionnels
-- selon la configuration et le mode RAM faible.

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

{ :plan_optional_workers } = require "lib.worker_plan"

describe "lib.worker_plan", ->
  describe "plan_optional_workers", ->
    -- ── Cas lowmem actif ──────────────────────────────────────────────
    describe "en mode lowmem", ->
      it "désactive tls même si nfqueue.sni est configuré", ->
        cfg = { nfqueue: { sni: "6" }, doh: {} }
        r = plan_optional_workers cfg, true
        assert.is_false r.tls

      it "désactive doh même si doh.enabled est vrai", ->
        cfg = { nfqueue: {}, doh: { enabled: true } }
        r = plan_optional_workers cfg, true
        assert.is_false r.doh

      it "n'affecte pas sip (sip reste actif si configuré)", ->
        cfg = { nfqueue: { sip: "12", sni: "6" }, doh: { enabled: true } }
        r = plan_optional_workers cfg, true
        assert.is_true r.sip

      it "désactive tls et doh mais garde sip", ->
        cfg = { nfqueue: { sip: "12", sni: "6" }, doh: { enabled: true } }
        r = plan_optional_workers cfg, true
        assert.is_false r.tls
        assert.is_false r.doh
        assert.is_true  r.sip

    -- ── Cas lowmem inactif ────────────────────────────────────────────
    describe "hors mode lowmem", ->
      it "active tls si nfqueue.sni est configuré", ->
        cfg = { nfqueue: { sni: "6" }, doh: {} }
        r = plan_optional_workers cfg, false
        assert.is_true r.tls

      it "active doh si doh.enabled est vrai", ->
        cfg = { nfqueue: {}, doh: { enabled: true } }
        r = plan_optional_workers cfg, false
        assert.is_true r.doh

      it "active sip si nfqueue.sip est configuré", ->
        cfg = { nfqueue: { sip: "12" }, doh: {} }
        r = plan_optional_workers cfg, false
        assert.is_true r.sip

      it "active tls, doh et sip simultanément", ->
        cfg = { nfqueue: { sip: "12", sni: "6" }, doh: { enabled: true } }
        r = plan_optional_workers cfg, false
        assert.is_true r.tls
        assert.is_true r.doh
        assert.is_true r.sip

    -- ── Cas limites ───────────────────────────────────────────────────
    describe "cas limites", ->
      it "renvoie false pour tous si nfqueue et doh sont vides", ->
        r = plan_optional_workers { nfqueue: {}, doh: {} }, false
        assert.is_false r.sip
        assert.is_false r.tls
        assert.is_false r.doh

      it "tolère cfg sans clé nfqueue", ->
        r = plan_optional_workers { doh: { enabled: true } }, false
        assert.is_true  r.doh
        assert.is_false r.sip
        assert.is_false r.tls

      it "tolère cfg sans clé doh", ->
        r = plan_optional_workers { nfqueue: { sni: "6" } }, false
        assert.is_true  r.tls
        assert.is_false r.doh

      it "nfqueue.sni=false (falsy) ne lance pas tls", ->
        r = plan_optional_workers { nfqueue: { sni: false }, doh: {} }, false
        assert.is_false r.tls

      it "doh.enabled=false ne lance pas doh", ->
        r = plan_optional_workers { nfqueue: {}, doh: { enabled: false } }, false
        assert.is_false r.doh
