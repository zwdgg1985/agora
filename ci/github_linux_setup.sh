#!/bin/bash

set -xeu
set -o pipefail

sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install libsqlite3-dev
sudo apt-get install libsodium-dev
sudo apt-get install g++-9

mkdir -p $HOME/bin/
ln -s `which gcc-9` $HOME/bin/gcc # /usr/bin/gcc-9
ln -s `which g++-9` $HOME/bin/g++ # /usr/bin/g++-9

pushd $HOME
wget https://github.com/jedisct1/libsodium/archive/1.0.18-RELEASE.tar.gz
tar xvfz 1.0.18-RELEASE.tar.gz
cd libsodium-1.0.18-RELEASE
./configure
make -j4
sudo make install
sudo ldconfig # Refresh cache
popd
