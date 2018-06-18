#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/sprouts.png
ICON_DST=../../src/qt/res/icons/sprouts.ico
convert ${ICON_SRC} -resize 16x16 sprouts-16.png
convert ${ICON_SRC} -resize 32x32 sprouts-32.png
convert ${ICON_SRC} -resize 48x48 sprouts-48.png
convert sprouts-48.png sprouts-32.png sprouts-16.png ${ICON_DST}

