from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from base64 import *


ct = b'XieqPMvg9A+LxlkvQvGh2z/ooR9oom/Qrk8XnF4f8OgU5Aym3oUDAaREtZKYPK1aKfCpULVCE2831zhbslzuAtyrzvPf8ruYFsy2rn0PHTo='

ct = b64decode(ct).hex()

iv = bytes.fromhex(ct[:16])
ct = bytes.fromhex(ct[16:])

key = b'persever'

cipher = DES.new(key, DES.MODE_CBC, iv = iv)



print(cipher.decrypt(ct))
print(bytes.fromhex(cipher.decrypt(ct)[:-4].decode()))