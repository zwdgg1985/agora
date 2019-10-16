#!/bin/bash

set -xeu
set -o pipefail

brew install sqlite3

mkdir -p $HOME/Dependencies/
wget -P $HOME/Dependencies/ https://homebrew.bintray.com/bottles/libsodium-1.0.18.high_sierra.bottle.tar.gz
tar -C /usr/local/Cellar/ -xf $HOME/Dependencies/libsodium-1.0.18.high_sierra.bottle.tar.gz
brew link libsodium

export PATH="${PATH-}:$HOME/bin/"
export LIBRARY_PATH="${LIBRARY_PATH-}:/usr/local/lib/"
export PKG_CONFIG_PATH="/usr/local/opt/sqlite/lib/pkgconfig"
