#!/usr/bin/env moon

-- Minimal auth smoke test based on curl via io.popen.
-- Checks:
--   1. POST /login returns 200 and a Set-Cookie header
--   2. GET /ping with that cookie returns 204

DEFAULT_URL = "https://custos.stemarie.dynv6.net:33443"
DEFAULT_USER = "j@prn.ovh"
DEFAULT_PASS = "patouche"

parse_args = ->
  url = arg and arg[1] or DEFAULT_URL
  user = arg and arg[2] or DEFAULT_USER
  pass = arg and arg[3] or DEFAULT_PASS
  url, user, pass

run = (cmd) ->
  io.stderr\write ">> #{cmd}\n"
  fh = assert io.popen("#{cmd} 2>&1")
  out = fh\read "*a"
  ok, why, code = fh\close!
  io.stderr\write out if out and out != ""
  io.stderr\write "\n" if out and out != "" and out\sub(-1) != "\n"
  io.stderr\write "curl exit: #{tostring(code or why or ok)}\n" unless ok
  ok, out, code or why

extract_status = (text) ->
  tonumber text\match("HTTP/%d%.%d%s+(%d%d%d)") or "0"

extract_set_cookie = (text) ->
  cookies = {}
  for line in tostring(text)\gmatch("[^\r\n]+")
    cookie = line\match("[Ss]et%-[Cc]ookie:%s*([^;]+)")
    if cookie and cookie != ""
      cookies[#cookies + 1] = cookie
  table.concat cookies, "; "

main = ->
  url, user, pass = parse_args!
  base = url\gsub("/+$", "")

  login_cmd = table.concat {
    "curl -k -v -s -D - -o /dev/null"
    "-H 'Content-Type: application/x-www-form-urlencoded'"
    "-d 'user=#{user}&password=#{pass}'"
    "#{base}/login"
  }, " "

  ok1, login_out, login_status = run login_cmd
  unless ok1
    io.stderr\write "LOGIN command failed (status #{tostring(login_status)})\n"
    io.stderr\write "Command: #{login_cmd}\n"
    os.exit 1

  login_code = extract_status login_out
  unless login_code == 200
    io.stderr\write "LOGIN expected 200, got #{login_code}\n"
    io.stderr\write "Command: #{login_cmd}\n"
    os.exit 1

  cookie = extract_set_cookie login_out
  unless cookie and cookie != ""
    io.stderr\write "LOGIN did not return a usable Set-Cookie header\n"
    io.stderr\write "Command: #{login_cmd}\n"
    os.exit 1

  io.stderr\write "LOGIN cookie: #{cookie}\n"

  ping_cmd = table.concat {
    "curl -k -v -s -D - -o /dev/null"
    "-H 'Cookie: #{cookie}'"
    "#{base}/ping"
  }, " "

  ok2, ping_out, ping_status = run ping_cmd
  unless ok2
    io.stderr\write "PING command failed (status #{tostring(ping_status)})\n"
    io.stderr\write "Command: #{ping_cmd}\n"
    os.exit 1

  ping_code = extract_status ping_out
  unless ping_code == 204
    io.stderr\write "PING expected 204, got #{ping_code}\n"
    io.stderr\write "Command: #{ping_cmd}\n"
    os.exit 1

  print "OK"
  os.exit 0

main!
