--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Point d'entrée script du micro-banc de profilage du hot path.
-- Exécuté directement par luajit (`luajit lua/bench/hotpath_cli.lua ...`) :
-- transmet les arguments de la ligne de commande à bench.hotpath.main.

hp = require "bench.hotpath"
hp.main [ a for a in *arg ]
