#!/bin/bash -ev

mkdir -p ~/.sprouts
echo "rpcuser=username" >>~/.sprouts/sprouts.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >>~/.sprouts/sprouts.conf

