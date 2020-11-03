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

cookiejar = Dict{String, Set{HTTP.Cookie}}()

function login(pvwahost, pvwauri, causer, capass)
        if capass == ""
                capass = Base.getpass("Please enter your CyberArk password")
        else
                capass = convert(Base.SecretBuffer, capass)
        end
        url = "$pvwauri/api/auth/ldap/logon"
        headers = ["Content-Type" => "application/json"]
        payload = JSON.json(Dict(
                "username" => causer,
                "password" => read(capass, String),
                "newPassword" => nothing,
                "type" => "ldap",
                "secureMode" => true,
                "additionalInfo" => ""
        ))
        response = HTTP.request("POST", url, headers, payload; require_ssl_verification = false, cookies = true, cookiejar = cookiejar)
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
        url = "$pvwauri/api/$query"
        headers = ["Content-Type" => "application/json", "X-CA66666" => headerauth ]
        response = HTTP.request("GET", url, headers; require_ssl_verification = false, cookies = true, cookiejar = cookiejar)
        #return String(response.body)
        if response.status == 200
                return JSON.parse(String(response.body))
        else
                error(response.status)
        end
        # return response.body
end

#Make webreq a little more friendly
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

#Try a login initially.
headerauth = login(pvwahost, pvwauri, causer, capass)

#List accounts.
action = request("ExtendedAccounts")
