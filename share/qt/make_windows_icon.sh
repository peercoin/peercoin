#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/peershares.png
ICON_DST=../../src/qt/res/icons/peershares.ico
convert ${ICON_SRC} -resize 16x16 peershares-16.png
convert ${ICON_SRC} -resize 32x32 peershares-32.png
convert ${ICON_SRC} -resize 48x48 peershares-48.png
convert peershares-48.png peershares-32.png peershares-16.png ${ICON_DST}

