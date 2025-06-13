from PIL import Image

im = Image.open('og.png')
im_enc = Image.open('og_enc.png')
flag_enc = Image.open('flag_enc.png')

print(im.mode)
print(im_enc.mode)
print(flag_enc.mode)