bit =
  band: (a, b) -> a & b
  bor: (a, b) -> a | b
  -- MoonScript parses `a ~ b` ambiguously; express XOR with identities.
  bxor: (a, b) -> (a | b) & (~(a & b))
  bnot: (a) -> ~a
  lshift: (a, n) -> a << n
  rshift: (a, n) -> a >> n
  arshift: (a, n) -> a >> n

return bit
