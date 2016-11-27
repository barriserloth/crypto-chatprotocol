#AESCipher implementation from https://gist.github.com/crmccreary/5610068 

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

def toHex(number):
    bytes = ""
    while number > 0:
        byte = number % 256
        number = number - byte
        if number >= 256:
            number = number/256
        bytes = bytes + str(chr(byte))
    return bytes

''' Returns a random 16 byte key for use in AES '''
def generateKey():
        return toHex(getrandbits(128))

class AESCipher:
    def __init__(self, key):
        #Requires hex encoded key
        self.key = key.decode("hex")

    def encrypt (self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return (iv + cipher.encrypt(raw)).encode("hex")

    def decrypt(self, enc):
        enc = enc.decode("hex")
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc))

    
