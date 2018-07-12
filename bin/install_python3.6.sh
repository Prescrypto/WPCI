#!/usr/bin/env bash

echo "=> Begin installing python3.6..."
sudo apt-get update
sudo apt-get install -y build-essential libc6-dev
sudo apt-get install -y libncurses5-dev libncursesw5-dev libreadline6-dev
sudo apt-get install -y libdb5.3-dev libgdbm-dev libsqlite3-dev libssl-dev
sudo apt-get install -y libbz2-dev libexpat1-dev liblzma-dev zlib1g-dev
# get source code
cd $HOME
wget https://www.python.org/ftp/python/3.6.6/Python-3.6.6.tgz
tar -zxvf Python-3.6.6.tgz
cd Python-3.6.6
# build & install
echo "=> build & install..."
./configure
make -j4          # using 4 threads for some speed
sudo make install
# cleanup
cd ..
sudo rm -fr ./Python-3.6.6*
# upgrade (just in case)
sudo pip3 install -U pip
sudo pip3 install -U setuptools
echo "=> End installing python3.6..."

