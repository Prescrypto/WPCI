#!/usr/bin/env bash

echo "=> Start config box..."
sudo apt-get install -y build-essential libssl-dev wget python-pip python-dev libffi-dev
sudo pip install -U pip
sudo apt-get install libssl-dev libcurl4-openssl-dev

echo "=> Start mongodb service..."
sudo service mongod start

# verify
echo "=>verify python versions..."
python3 --version
pip3 --version

echo "Installing python requirements"
sudo pip3 install -r /vagrant/requirements.txt

echo "*******************************************"
echo "Install texlive packages "
echo "*******************************************"
cd /vagrant/
sudo env PATH="$PATH" tlmgr install $(cat texlive.packages)

echo "Installed Latex with Packages!!"


echo "=> End config box..."
