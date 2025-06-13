from netpbmfile import *
import numpy
data = b''

for i in range(1, 87):
    with open('files/image_'+str(i)+'.pbm','rb') as f:
        data += f.read()[13:]
        # print(f.read()[13:])
with open('files/image_1.pbm','rb') as f:
    data = f.read()[:13] + data
with open('files/bro.pbm','wb+') as f:
    f.write(data)
# print(data[:13])
