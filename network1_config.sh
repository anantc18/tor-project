#!/usr/bin/bash

if [ "$NODE_NAME" = "entry" ] 
then
    export TOR_PRIVATE_KEY="7lVjtbrfz3AW_-kvjY8_0iI_ygkdDNr87SPxxQZCrh8="
    export TOR_SELF_IP="10.0.1.20"
    export TOR_PREV_NEIGHBOR="10.0.0.20"
    export TOR_NEXT_NEIGHBOR="10.0.3.20"
    export TOR_CIRCUIT_ID="111"

elif [ "$NODE_NAME" = "middle" ]
then
    export TOR_PRIVATE_KEY="QUT4K3xhT_cnMKAkL8FNqSDon-UTdM9NlRov6oG764s="
    export TOR_SELF_IP="10.0.3.20"
    export TOR_PREV_NEIGHBOR="10.0.1.20"
    export TOR_NEXT_NEIGHBOR="10.0.5.20"
    export TOR_CIRCUIT_ID="111"

elif [ "$NODE_NAME" = "exit" ]
then
    export TOR_PRIVATE_KEY="0UxtjHYSht-zdUSv2Lh-Ckg5ZCtU9owJtNeHfHNGkf4="
    export TOR_SELF_IP="10.0.5.20"
    export TOR_PREV_NEIGHBOR="10.0.3.20"
    export TOR_NEXT_NEIGHBOR="0.0.0.0"
    export TOR_CIRCUIT_ID="111"
fi

