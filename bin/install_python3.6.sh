#!/usr/bin/env bash
if command -v python3 &>/dev/null; then
    echo "Python 3 is installed"
else
    echo "=> Begin installing python3.6..."
    sudo apt-get update && sudo apt-get upgrade
    sudo apt-get install -y make build-essential libssl-dev zlib1g-dev
    sudo apt-get install -y libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm
    sudo apt-get install -y libncurses5-dev  libncursesw5-dev xz-utils tk-dev
    # get source code
    cd $HOME
    wget https://www.python.org/ftp/python/3.6.6/Python-3.6.6.tgz
    tar -zxvf Python-3.6.6.tgz
    cd Python-3.6.6
    # build & install
    echo "=> build & install..."
    ./configure
    make -j8          # using 8 threads for some speed
    sudo make install  # is used to prevent replacing the default python binary file
    # cleanup
    cd ..
    sudo rm -fr ./Python-3.6.6*
    # upgrade (just in case)
    sudo pip3 install -U pip
    sudo pip3 install -U setuptools
    echo "=> End installing python3.6..."
fi

