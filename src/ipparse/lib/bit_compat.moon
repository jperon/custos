--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Bitwise Operations Compatibility Module
-- This module provides bitwise operations compatible with Lua 5.1 through 5.5.
-- It automatically selects the appropriate bit library based on the Lua version:
-- - LuaJIT/Lua 5.1: Uses the `bit` library
-- - Lua 5.2: Uses the `bit32` library
-- - Lua 5.3+: Uses native bitwise operators
--
-- @module bit_compat

-- Try to load the bit library (LuaJIT/Lua 5.1)
ok, bit = pcall require, "bit"
return bit if ok
-- Fall back to bit32 (Lua 5.2)
ok, bit = pcall require, "bit32"
return bit if ok
-- Use native operators for Lua 5.3+
ok, bit = pcall require, "bit53"
return bit
