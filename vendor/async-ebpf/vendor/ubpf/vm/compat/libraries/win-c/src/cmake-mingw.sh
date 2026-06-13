#!/bin/sh
mkdir build
INSTALL_PREFIX=`pwd | sed 's/^\/c/C:/'`
cd build
cmake -D CMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} ..
