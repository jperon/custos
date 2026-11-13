--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Point d'entrée script du banc CPU du worker nft.
-- Exécuté directement par luajit (`luajit lua/bench/nft_cpu_cli.lua ...`) :
-- transmet les arguments de la ligne de commande à bench.nft_cpu.main.

nc = require "bench.nft_cpu"
nc.main [ a for a in *arg ]
