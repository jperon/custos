do
  local _with_0 = require("html")
  print(_with_0.div({
    id = "test"
  }, {
    class = "example"
  }, "Test", _with_0.br(), "et ", _with_0.em("voilà !")))
  return _with_0
end
