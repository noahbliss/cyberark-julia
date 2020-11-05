#!/usr/bin/env julia
import HTTP
import JSON
using DelimitedFiles

#settingsfile = "settings.conf"
backupsettingsfile = "$(homedir())/.config/cyberark-julia/settings.conf"
@isdefined(settingsfile) || isfile(backupsettingsfile) && (settingsfile = backupsettingsfile)
isfile(settingsfile) || println("Settings file is missing.") && exit(1)

importedvars = readdlm(settingsfile, '=', String; skipblanks=true)
a2var(key, a) = (c=1; for i in a[:, 1]; i == key && return a[c, 2]; c+=1; end || error("$key not found"))

pvwahost = a2var("pvwahost", importedvars)
pvwauri = a2var("pvwauri", importedvars)
causer = a2var("causer", importedvars)
capass = a2var("capass", importedvars) #We'll replace this with a SecretBuffer almost immediately.

# Used in makedatastructures
viewlist = Dict()
accountlist = Dict()

# Used in most API calls.
cookiejar = Dict{String, Set{HTTP.Cookie}}()

function login(pvwahost, pvwauri, causer, capass)
        if capass == ""
                capass = Base.getpass("Please enter your CyberArk password")
        else
                capass = convert(Base.SecretBuffer, capass)
        end
        uri = "$pvwauri/api/auth/ldap/logon"
        headers = ["Content-Type" => "application/json"]
        payload = JSON.json(Dict(
                "username" => causer,
                "password" => read(capass, String),
                "newPassword" => nothing,
                "type" => "ldap",
                "secureMode" => true,
                "additionalInfo" => ""
        ))
        response = HTTP.request("POST", uri, headers, payload; require_ssl_verification = false, cookies = true, cookiejar = cookiejar)
        Base.shred!(capass)
        if response.status == 200
                for set in cookiejar[pvwahost]
                        if set.name == "CA66666"
                                return set.value
                                break
                        end
                end
        else
                error("Response not 200.")
        end
end

function webreq(pvwauri, cookiejar, headerauth, query)
        uri = "$pvwauri/api/$query"
        headers = ["Content-Type" => "application/json", "X-CA66666" => headerauth ]
        response = HTTP.request("GET", uri, headers; require_ssl_verification = false, cookies = true, cookiejar = cookiejar)
        #return String(response.body)
        if response.status == 200
                return JSON.parse(String(response.body))
        else
                error(response.status)
        end
        # return response.body
end

# Make webreq a little more friendly
function request(req)
        try response = webreq(pvwauri, cookiejar, headerauth, req)
                return response
        catch e
                if e.status == 401
                        global headerauth = login(pvwahost, pvwauri, causer, capass)
                        response = webreq(pvwauri, cookiejar, headerauth, req)
                else
                        return e.status
                end
        end
end

function getpsm(pvwauri, cookiejar, headerauth, accountid, reason, target)
        uri = "$pvwauri/api/Accounts/$accountid/PSMConnect"
        headers = ["Content-Type" => "application/json", "X-CA66666" => headerauth ]
        payload = JSON.json(Dict(
                "reason" => reason,
                "ConnectionComponent" => "PSM-RDP",
                "ConnectionParams" => Dict(
                        "AllowMappingLocalDrives" => Dict(
                                "value" => "Yes",
                                "ShouldSave" => false
                        ),
                        "PSMRemoteMachine" => Dict(
                                "value" => target,
                                "ShouldSave" => false
                        )
                )
        ))
        response = HTTP.request("POST", uri, headers, payload; require_ssl_verification = false, cookies = true, cookiejar = cookiejar)
        if response.status == 200
                #return JSON.parse(String(response.body))
                return String(response.body)
        else
                error(response.status)
        end
end

function makedatastructures(caaccounts)
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
                global viewlist[safe][name] = Dict(
                        "Address" => addr,
                        "Username" => user,
                        "AccountID" => id
                )
                global accountlist[name] = Dict(
                        "Address" => addr,
                        "Username" => user,
                        "AccountID" => id,
                        "Safe" => safe
                )
        end
        return
end


# Try a login initially.
headerauth = login(pvwahost, pvwauri, causer, capass)

# List accounts. This variable stores the original format from the CyberArk API.
caaccounts = request("ExtendedAccounts")
# Make our format data structures.
makedatastructures(caaccounts)
#accountlist and viewlist



viewlist
accname = "LONGNAME_OF_ACCOUNT"
target = "FQDN_OR_IP_OF_TARGET"

accountid = accountlist[accname]["AccountID"]
psmstr = getpsm(pvwauri, cookiejar, headerauth, accountid, reason, target)

filename = "rdpswap.rdp"
open(filename, "w")
write(filename, psmstr)
run(`ca-rdp $filename`)
