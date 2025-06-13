import os
import random

from PIL import Image


def get_random_pixel(mode):
    match mode:
        case 'RGB':
            r = random.getrandbits(24)
            t = (r & 0xff, r >> 8 & 0xff, r >> 16 & 0xff)
        case 'RGBA':
            r = random.getrandbits(32)
            t = (r & 0xff, r >> 8 & 0xff, r >> 16 & 0xff, r >> 24 & 0xff)
        case 'L':
            r = random.getrandbits(8)
            t = (r & 0xff,)
        case _:
            # assume RGB
            r = random.getrandbits(24)
            t = (r & 0xff, r >> 8 & 0xff, r >> 16 & 0xff)
    return t


def create_key(image):
    pixels = list(image.getdata())
    pixels.sort()
    k = {}
    k_inv = {}
    for p in pixels:
        if p in k:
            continue

        x = get_random_pixel(image.mode)
        while x in k_inv:
            x = get_random_pixel(image.mode)
        k[p] = x
        k_inv[x] = p
    return k, k_inv


def encrypt_image(image):
    k, _ = create_key(image)
    n = Image.new(image.mode, image.size, 0)
    for x in range(image.size[0]):
        for y in range(image.size[1]):
            n.putpixel((x, y), k[image.getpixel((x, y))])

    return n


def main():
    im = Image.open('og.png')
    n = encrypt_image(im)
    n.save('og_enc.png')

    f = encrypt_image(Image.open('flag.png'))
    f.save('flag_enc.png')
    os.remove('flag.png')


if __name__ == '__main__':
    main()
