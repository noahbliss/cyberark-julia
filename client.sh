#!/usr/bin/env bash
# JUST CLIENT BITS BELOW:

#We will only support LONG FORMAT arguments.
validflags="username address connection target reason"
count=1
for arg in $@
do
    match=0
    argval=$1
    for flag in $validflags
    do
        sflag="--"$flag
        if [ "$argval" == "$sflag" ]
        then
            declare $flag=$2
            match=1
        fi
    done
        if [ "$match" == "1" ]
    then
        shift 2
    else
        leftovers=$(echo $leftovers $argval)
        shift
    fi
    count=$(($count+1))
done
#Cleanup then restore the leftovers
shift $#
set -- $leftovers

#settingsfile = "settings.conf"
usersettingsfile="$HOME/.config/cyberark-julia/settings.conf"
if [ -z $settingsfile ]; then settingsfile=$usersettingsfile; fi
if ! [ -f $settingsfile ]; then echo "Settings file is missing."; exit 1; fi
source $usersettingsfile


login() {
        curl --header "Content-Type: application/json" \
          --request POST \
          --data '{"causer":"'"$causer"'","capass":"'"$capass"'","pvwauri":"'"$pvwauri"'","method":"'"$method"'"}' \
          "http://localhost:8001/login"
        capass="notyourpassword"
}

read -sp "Enter your CyberArk password (will not echo): " capass
echo #make a new line

login
return=$?
echo #make a new line
echo $return

# ---
#
# function webreq(username, address, connection, target, reason)
#         HTTP.request("POST", "http://localhost:8001/psmconnect", [("Content-Type", "application/json")],
#                 JSON.json(Dict(
#                         "username" => username,
#                         "address" => address,
#                         "connection" => connection,
#                         "target" => target,
#                         "reason" => reason
#         )))
# end
#
# #Make webreq a little more friendly
# function psmconnect(username, address, connection, target, reason)
#         try response = webreq(username, address, connection, target, reason)
#                 return String(response.body)
#         catch e
#                 try if e.status == 401
#                                 capass = Base.getpass("Please enter your CyberArk password")
#                                 login(causer, capass)
#                                 Base.shred!(capass)
#                                 response = webreq(username, address, connection, target, reason)
#                                 return String(response.body)
#                         end
#                 catch err
#                         return err
#                 end
#         end
# end
#
# psmstr = psmconnect(username, address, connection, target, reason)
#
# #psmstr = response.body |> String
#
# filename = "rdpswap.rdp"
# open(filename, "w")
# write(filename, psmstr)
# run(`ca-rdp $filename`)
# #rm(filename) #This is handled by ca-rdp
