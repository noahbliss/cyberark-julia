#!/usr/bin/env julia
import HTTP
import JSON
using DelimitedFiles
using CyberArkPVWAClient

#settingsfile = "settings.conf"
backupsettingsfile = "$(homedir())/.config/cyberark-julia/settings.conf"
@isdefined(settingsfile) || isfile(backupsettingsfile) && (settingsfile = backupsettingsfile)
isfile(settingsfile) || println("Settings file is missing.") && exit(1)

importedvars = readdlm(settingsfile, '=', String; skipblanks=true)
a2var(key, a) = (c=1; for i in a[:, 1]; i == key && return a[c, 2]; c+=1; end || error("$key not found"))

pvwauri = a2var("pvwauri", importedvars)
method = a2var("method", importedvars)
causer = a2var("causer", importedvars)



function makedatastructures(caaccounts)
        viewlist = Dict()
        accountlist = dict()
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
        return
end


######

# Make webreq a little more friendly
function request(cookieset, query)
        try response = CyberArkPVWAClient.request(pvwauri, cookieset, query)
                return response
        catch e
                if e.status == 401
                        global capass = Base.getpass("Please enter your CyberArk password")
                        global cookieset = CyberArkPVWAClient.login(pvwauri, method, causer, capass)
                        response = CyberArkPVWAClient.request(pvwauri, cookieset, headerauth, query)
                else
                        return e.status
                end
        end
end


# Try a login initially.
#headerauth = login(pvwauri, method, causer, capass)
capass = Base.getpass("Please enter your CyberArk password")
cookieset = CyberArkPVWAClient.login(pvwauri, method, causer, capass)

# List accounts. This variable stores the original format from the CyberArk API.
caaccounts = CyberArkPVWAClient.request(pvwauri, cookieset, "ExtendedAccounts")

# Using request will automatically prompt for password if the previous cookie expired.
caaccounts = request(cookieset, "ExtendedAccounts")


# Make our format data structures.
# Used in makedatastructures
viewlist = Dict()
accountlist = Dict()
makedatastructures(caaccounts)
#accountlist and viewlist

accname = "LONGNAME_OF_ACCOUNT"
target = "FQDN_OR_IP_OF_TARGET"
reason = "Because I want to."
# Figure out the account ID (less friendly numbers) of the account.


accountid = accountlist[accname]["AccountID"]
# Request the generated RDP file.

psmstr = CyberArkPVWAClient.psmconnect(pvwauri, cookieset, accountid, reason, target)

filename = "rdpswap.rdp"
open(filename, "w")
write(filename, psmstr)
run(`ca-rdp $filename`)
#rm(filename) #This is handled by ca-rdp
