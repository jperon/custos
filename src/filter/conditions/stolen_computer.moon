-- src/filter/conditions/stolen_computer.moon
-- Condition : vérifie si l'adresse MAC source est dans une liste noire d'ordinateurs volés.
-- Retourne true avec un message spécifique si trouvé.

stolen_computer = (cfg) ->
  (macs) ->
    blacklist = {}
    for mac in *macs
      blacklist[mac\lower!] = true
    (req) ->
      _mac = req.mac
      unless _mac
        return false, "MAC not available"
      if blacklist[_mac\lower!]
        return true, "Stolen computer: #{_mac}"
      else
        return false, "MAC #{_mac} not in blacklist"

stolen_computer
