#! /usr/bin/env nix-shell
#! nix-shell -p bash imagemagick -i bash

set -e
set -x

if [ -d ./test-images ]; then
	echo "test-images directory exists, please remove it!"
	exit 1
fi

mkdir -p ./test-images

for SCALE in $(seq 0.1 .3 10); do
	magick /mydata/big_building.ppm -resize "${SCALE}%" "PNG:./test-images/big_building_$(printf "%05.1f\n" "$SCALE")p.png"
done
