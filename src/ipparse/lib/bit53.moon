bit =
  band: (a, b) -> a & b
  bor: (a, b) -> a | b
  bxor: (a, b) -> a ~ b
  bnot: (a) -> ~a
  lshift: (a, n) -> a << n
  rshift: (a, n) -> a >> n
  arshift: (a, n) -> a >> n  -- arithmetic right shift (same as logical for positive numbers)

return bit
