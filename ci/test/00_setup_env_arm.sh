#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export HOST=arm-linux-gnueabihf
export DPKG_ADD_ARCH="armhf"
# The GCC cross package provides the ARM sysroot, libstdc++, and binutils used by Clang.
export PACKAGES="clang python3-zmq g++-arm-linux-gnueabihf libc6:armhf libstdc++6:armhf libfontconfig1:armhf libxcb1:armhf"
export CONTAINER_NAME=ci_arm_linux
export CI_IMAGE_NAME_TAG="mirror.gcr.io/debian:trixie"
export CI_IMAGE_PLATFORM="linux/arm64"
export DEP_OPTS="CC='clang --target=${HOST}' CXX='clang++ --target=${HOST}'"
export GOAL="install"
export CI_LIMIT_STACK_SIZE=1
export BITCOIN_CONFIG=" \
  --preset=dev-mode \
  -DREDUCE_EXPORTS=ON \
"
