#!/bin/bash

source secrets.sh

FLAGS="all_flags.txt"
rm "new_flags.enc"
rm "flag.ppm"
rm "tail"

while read flag; do
	magick -background white -fill blue -pointsize 72 -size "$X"x"$Y" -gravity North caption:"$flag" flag.ppm
	tail -n +4 flag.ppm > tail
	openssl enc -aes-256-ecb -pbkdf2 -nosalt -pass pass:"$KEY" -in tail >> "new_flags.enc"
done < "$FLAGS"

