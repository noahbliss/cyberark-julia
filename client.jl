#!/usr/bin/env julia
# JUST CLIENT BITS BELOW:
import HTTP
import JSON
using ArgParse
using DelimitedFiles

function parse_commandline()
        s = ArgParseSettings()
        @add_arg_table! s begin
                "--username", "-u"
                        help = "Username of the requested CyberArk credential."
                        required = true
                "--address", "-a"
                        help = "Address listed in the requested CyberArk credential."
                        required = true
                "--connection", "-c"
                        default = "PSM-RDP"
                        help = "Connection component we will use. Default: PSM-RDP"
                "--target", "-t"
                        help = "IP or FQDN of the system we want to connect to with the requested credential."
                        required = true
                "--reason", "-r"
                        default = "Connection brokered through Remmina, specifiying reason is not yet implemented."
                        help = "The reason for the connection."
        end
        return parse_args(s)
end

args = parse_commandline()

#settingsfile = "settings.conf"
backupsettingsfile = "$(homedir())/.config/cyberark-julia/settings.conf"
@isdefined(settingsfile) || isfile(backupsettingsfile) && (settingsfile = backupsettingsfile)
isfile(settingsfile) || println("Settings file is missing.") && exit(1)

importedvars = readdlm(settingsfile, '=', String; skipblanks=true)
a2var(key, a) = (c=1; for i in a[:, 1]; i == key && return a[c, 2]; c+=1; end || error("$key not found"))

pvwauri = a2var("pvwauri", importedvars) # https://cyberark.domain.local/PasswordVault
method = a2var("method", importedvars) # ldap
causer = a2var("causer", importedvars) # noah.bliss
username = args["username"] # domain-admin
address = args["address"] # domain.local
connection = args["connection"] # PSM-RDP
target = args["target"] # dc01.domain.local
reason = args["reason"] # Because I want to.

# capass = Base.getpass("Please enter your CyberArk password")

function login(causer, capass)
        response = HTTP.request("POST", "http://localhost:8001/login", [("Content-Type", "application/json")],
                        JSON.json(Dict(
                                "causer" => causer,
                                "capass" => read(capass, String),
                                "pvwauri" => pvwauri,
                                "method" => method
                )))
        Base.shred!(capass)
end

function webreq(username, address, connection, target, reason)
        HTTP.request("POST", "http://localhost:8001/psmconnect", [("Content-Type", "application/json")],
                JSON.json(Dict(
                        "username" => username,
                        "address" => address,
                        "connection" => connection,
                        "target" => target,
                        "reason" => reason
        )))
end

#Make webreq a little more friendly
function psmconnect(username, address, connection, target, reason)
        try response = webreq(username, address, connection, target, reason)
                return String(response.body)
        catch e
                try if e.status == 401
                                capass = Base.getpass("Please enter your CyberArk password")
                                login(causer, capass)
                                Base.shred!(capass)
                                response = webreq(username, address, connection, target, reason)
                                return String(response.body)
                        end
                catch err
                        return err
                end
        end
end

psmstr = psmconnect(username, address, connection, target, reason)

#psmstr = response.body |> String

filename = "rdpswap.rdp"
open(filename, "w")
write(filename, psmstr)
run(`ca-rdp $filename`)
#rm(filename) #This is handled by ca-rdp
