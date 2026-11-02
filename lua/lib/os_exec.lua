local exec_ok
exec_ok = function(ret)
  return ret == 0 or ret == true
end
return {
  exec_ok = exec_ok
}
