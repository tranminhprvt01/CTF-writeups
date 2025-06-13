#!/bin/bash

source secrets.sh

ENC="all_flags.enc"
rm -rf images

mkdir -p images

# Decrypt the contents of the "flag.enc" file and add the PPM header
#openssl enc -d -aes-256-ecb -pbkdf2 -nosalt -pass pass:"$KEY" -in "$ENC" -out temp.ppm
echo "P6" > "images/flag.ppm"
echo "$X $Y" >> "images/flag.ppm"
echo "65535" >> "images/flag.ppm"
cat  "$ENC" >> "images/flag.ppm"
