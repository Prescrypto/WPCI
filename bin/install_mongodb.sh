#!/usr/bin/env bash

# Script that install mongodb into debian jessy 64
echo "Installing mongo@3.4"
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install -y dirmngr
sudo apt-get install -y curl
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6

echo "deb http://repo.mongodb.org/apt/debian "$(lsb_release -sc)"/mongodb-org/3.4 main" | sudo tee /etc/apt/sources.list.d/mongodb-3.4.list

sudo apt-get update
# This is the version of mongoLab in heroku
sudo apt-get install -y mongodb-org


