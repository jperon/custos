-- tests/helpers/line_coverage_batch_setup.lua
-- Helper de la passe « batch » de `make coverage-split` : certains specs ne
-- passent pas isolément parce qu'ils attendent des symboles FFI déclarés par
-- un spec exécuté plus tôt dans la suite complète (ex.
-- tests/unit/ffi/ffi_defs_spec.lua, tests/unit/worker_responses_spec.lua :
-- « undeclared or implicit tag 'pollfd' » / `ffi.C.socket` absent). On amorce
-- `lib.socket` (qui déclare socket/bind/listen/accept/connect/pollfd) pour
-- retrouver l'état de la suite complète, puis on collecte comme d'habitude.
dofile("tests/helpers/line_coverage_setup.lua")

pcall(require, "lib.socket")
