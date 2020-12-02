#!/usr/bin/env bash

#Defaults
connection="PSM-RDP"
reason="Because I want to."
rdpswapfile="rdpswap.rdp"

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
    read -sp "Enter your CyberArk password (will not echo): " capass
    echo #make a new line
    resp=$(curl -s --header "Content-Type: application/json" \
        --request POST \
        --data '{"causer":"'"$causer"'","capass":"'"$capass"'","pvwauri":"'"$pvwauri"'","method":"'"$method"'"}' \
        "http://localhost:8001/login")
    capass="notyourpassword"
    if [ $resp == "OK" ]; then
        echo "Login response is good."
    fi
}

webreq() {
    resp=1337
    while [ $resp != "200" ]; do
        resp=$(curl -s -w "%{http_code}" -o "$rdpswapfile" --header "Content-Type: application/json" \
            --request POST \
            --data '{"username":"'"$username"'","address":"'"$address"'","connection":"'"$connection"'","target":"'"$target"'","reason":"'"$reason"'"}' \
            "http://localhost:8001/psmconnect")
        if [ $resp != "200" ]; then
            echo "Response $resp"
            login
        fi
    done
    echo "Response looks good! Wrote $rdpswapfile"
    ca-rdp $rdpswapfile
}


webreq
