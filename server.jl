#!/usr/bin/env julia
using DelimitedFiles
using CyberArkPVWAClient
import Genie, Genie.Router, Genie.Renderer.Json, Genie.Requests
import JSON
import HTTP

#settingsfile = "settings.conf"
backupsettingsfile = "$(homedir())/.config/cyberark-julia/settings.conf"
@isdefined(settingsfile) || isfile(backupsettingsfile) && (settingsfile = backupsettingsfile)
isfile(settingsfile) || println("Settings file is missing.") && exit(1)

importedvars = readdlm(settingsfile, '=', String; skipblanks=true)
a2var(key, a) = (c=1; for i in a[:, 1]; i == key && return a[c, 2]; c+=1; end || error("$key not found"))

pvwauri = a2var("pvwauri", importedvars) # https://cyberark.domain.local/PasswordVault
method = a2var("method", importedvars) # ldap
causer = a2var("causer", importedvars) # noah.bliss
cookieset = Set{HTTP.Cookies.Cookie}


function makedatastructures(caaccounts)
        viewlist = Dict()
        accountlist = Dict()
        for acc in caaccounts["Accounts"]
                # Alias data for sanity's sake
                safe = (try acc["Properties"]["Safe"] catch; nothing end)
                addr = (try acc["Properties"]["Address"] catch; nothing end)
                user = (try acc["Properties"]["UserName"] catch; nothing end)
                name = (try acc["Properties"]["Name"] catch; nothing end)
                id = (try acc["AccountID"] catch; nothing end)
                # Add the root key for the safe if it doesn't exist yet.
                try viewlist[safe] catch; global viewlist[safe] = Dict() end
                # Add our account
                viewlist[safe][name] = Dict(
                        "Address" => addr,
                        "Username" => user,
                        "AccountID" => id
                )
                accountlist[name] = Dict(
                        "Address" => addr,
                        "Username" => user,
                        "AccountID" => id,
                        "Safe" => safe
                )
        end
        global viewlist
        global accountlist
        return
end


######



function getaccountid(username, address, connection, caaccounts)
        for acc in caaccounts["Accounts"]#[1]
                if acc["Properties"]["UserName"] == username &&
                acc["Properties"]["Address"] == address &&
                haskey(acc["ActionsDisplay"]["ConnectionDisplay"]["ConnectionComponents"], connection)
                        return acc["AccountID"]
                end
        end
end



### Genie integration
Genie.route("/login", method = Genie.POST) do
  message = Genie.Requests.jsonpayload()
  pass = Base.SecretBuffer(message["capass"])
  try global cookieset = CyberArkPVWAClient.login(message["pvwauri"], message["method"], message["causer"], pass)
          Base.shred!(pass)
          # Refresh account list:
          global caaccounts = CyberArkPVWAClient.request(pvwauri, cookieset, "ExtendedAccounts")
          return("OK") # If we remove this line, we return the list of accounts to the requester. Potential security issue depending on use case.
  catch e # Make this throw a 401 itself.
          Base.shred!(pass)
          try e.status == 401 && return Genie.Responses.setstatus(401)
          catch e; return e; end
  end
end

Genie.route("/psmconnect", method = Genie.POST) do
  message = Genie.Requests.jsonpayload()
  # (:echo => (message["message"] * " ") ^ message["repeat"]) |> JSON.json
  accountid = ""
  try accountid = getaccountid(message["username"], message["address"], message["connection"], caaccounts)
  catch
          return Genie.Responses.setstatus(401) #accountid not set, lets bait out a login.
  end
  try psmstr = CyberArkPVWAClient.psmconnect(pvwauri, cookieset, accountid, message["reason"], message["target"])
          return psmstr
  catch e # Make this throw a 401 itself.
          try e.status == 401
                  return Genie.Responses.setstatus(401)
          catch e; return e; end
  end
end

Genie.up(8001)

# ---
#
# ### Build our UI
#
# # Try a login initially.
# capass = Base.getpass("Please enter your CyberArk password")
# cookieset = CyberArkPVWAClient.login(pvwauri, method, causer, capass)
#
# # List accounts. This variable stores the original format from the CyberArk API.
# caaccounts = CyberArkPVWAClient.request(pvwauri, cookieset, "ExtendedAccounts")
#
# # Make our human-friendlier data structures.
# # Used in makedatastructures
# viewlist = Dict()
# accountlist = Dict()
# makedatastructures(caaccounts)
