#!/usr/bin/env bash

echo "=> Start config box..."
sudo apt-get install -y build-essential libssl-dev wget python-pip python-dev libffi-dev
sudo pip install -U pip

echo "=> Start mongodb service..."
sudo service mongod start

# verify
echo "=>verify python versions..."
python3 --version
pip3 --version

echo "Installing python requirements"
sudo pip3 install -r /vagrant/requirements.txt

echo "=> End config box..."
