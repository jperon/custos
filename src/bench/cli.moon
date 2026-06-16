--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Point d'entrée script du harnais de benchmark.
-- Exécuté directement par luajit (`luajit lua/bench/cli.lua ...`) : transmet les
-- arguments de la ligne de commande à bench.run.main.

run = require "bench.run"
run.main [ a for a in *arg ]
