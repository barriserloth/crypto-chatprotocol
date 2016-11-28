#AESCipher implementation from https://gist.github.com/crmccreary/5610068 

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits

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
        car = Random.new().read(AES.key_size[1])
        return car

class AESCipher:
    def __init__(self, key):
        #Requires hex encoded key
        self.key = key

    def encrypt (self, raw):
        plength = AES.block_size - (len(raw) % AES.block_size)
        raw += chr(plength) * plength
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(raw)
        return (str(iv) + str(enc))

    def decrypt(self, enc):
        #enc = enc.decode("hex")
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(enc)
        msg = msg[:len(msg) - ord(msg[-1])]
        return msg 

    
