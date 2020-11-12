# JUST CLIENT BITS BELOW:
import HTTP
import JSON

#settingsfile = "settings.conf"
backupsettingsfile = "$(homedir())/.config/cyberark-julia/settings.conf"
@isdefined(settingsfile) || isfile(backupsettingsfile) && (settingsfile = backupsettingsfile)
isfile(settingsfile) || println("Settings file is missing.") && exit(1)

importedvars = readdlm(settingsfile, '=', String; skipblanks=true)
a2var(key, a) = (c=1; for i in a[:, 1]; i == key && return a[c, 2]; c+=1; end || error("$key not found"))

pvwauri = a2var("pvwauri", importedvars) # https://cyberark.domain.local/PasswordVault
method = a2var("method", importedvars) # ldap
causer = a2var("causer", importedvars) # noah.bliss

capass = Base.getpass("Please enter your CyberArk password")

response = HTTP.request("POST", "http://localhost:8001/login", [("Content-Type", "application/json")],
                JSON.json(Dict(
                        "causer" => causer,
                        "capass" => read(capass, String),
                        "pvwauri" => pvwauri,
                        "method" => method
        )))
Base.shred!(capass)


username = "domain-admin"
address = "domain.local"
connection = "PSM-RDP"
target = "dc01.domain.local"
reason = "Because I want to."



response = HTTP.request("POST", "http://localhost:8001/psmconnect", [("Content-Type", "application/json")],
                JSON.json(Dict(
                        "username" => username,
                        "address" => address,
                        "connection" => connection,
                        "target" => target,
                        "reason" => reason
        )))

psmstr = response.body |> String

# Make webreq a little more friendly
# function request(cookieset, query)
#         try response = CyberArkPVWAClient.request(pvwauri, cookieset, query)
#                 return response
#         catch e # This does weird things if we get other non-HTTP errors. Need to fix.
#                 if e.status == 401
#                         global capass = Base.getpass("Please enter your CyberArk password")
#                         global cookieset = CyberArkPVWAClient.login(pvwauri, method, causer, capass)
#                         response = CyberArkPVWAClient.request(pvwauri, cookieset, headerauth, query)
#                 else
#                         return e.status
#                 end
#         end
# end

filename = "rdpswap.rdp"
open(filename, "w")
write(filename, psmstr)
run(`ca-rdp $filename`)
#rm(filename) #This is handled by ca-rdp
