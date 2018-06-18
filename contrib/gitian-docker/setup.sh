#!/bin/bash

set -e
set -x

kvm-ok
service apt-cacher-ng start
ls -l /dev/kvm

cd /gitian-builder
./bin/make-base-vm --suite precise --arch i386
./bin/make-base-vm --suite precise --arch amd64

# linux
./bin/gbuild ../sprouts/contrib/gitian-descriptors/boost-linux.yml </dev/null
cp build/out/boost-linux*-1.55.0-gitian-r1.zip inputs/
./bin/gbuild ../sprouts/contrib/gitian-descriptors/deps-linux.yml </dev/null
cp build/out/sprouts-deps-linux*-gitian-r1.zip inputs/
# windows
./bin/gbuild ../sprouts/contrib/gitian-descriptors/boost-win.yml </dev/null
cp build/out/boost-win*-1.55.0-gitian-r1.zip inputs/
./bin/gbuild ../sprouts/contrib/gitian-descriptors/deps-win.yml </dev/null
cp build/out/sprouts-deps-win*-gitian-r1.zip inputs/
./bin/gbuild ../sprouts/contrib/gitian-descriptors/qt-win.yml </dev/null
cp build/out/qt-win*-5.7.1-gitian-r1.zip inputs/
# osx
./bin/gbuild --commit osxcross=master,libdmg-hfsplus=master ../sprouts/contrib/gitian-descriptors/osxcross.yml </dev/null
cp build/out/osxcross.tar.xz inputs/
./bin/gbuild ../sprouts/contrib/gitian-descriptors/deps-osx.yml </dev/null
cp build/out/sprouts-deps-osx-gitian-r1.tar.xz inputs/
./bin/gbuild ../sprouts/contrib/gitian-descriptors/qt-osx.yml </dev/null
cp build/out/qt-osx-5.5.0-gitian.tar.xz inputs/
