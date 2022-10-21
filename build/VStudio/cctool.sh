#!/bin/sh

if [ -x /opt/x86_64-linux-musl-native/bin/g++ ]; then
    # build with musl g++ if available (https://musl.cc/)
    /opt/x86_64-linux-musl-native/bin/g++ "$@"
else
    # build with default g++
    g++ "$@"
fi
