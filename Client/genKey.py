from Crypto.PublicKey import RSA
from Crypto import Random

rand_gen = Random.new().read
key = RSA.generate(2048, rand_gen)

pub_key = key.publickey().exportKey("PEM")
priv_key = key.exportKey("PEM")

#writing public key to file
pubKey = open('stevePubKey.pem', 'w')
pubKey.write(pub_key)
pubKey.close()

privKey = open('stevePrivKey.pem', 'w')
privKey.write(priv_key)
privKey.close()
