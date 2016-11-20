from Crypto.PublicKey import RSA

key = RSA.generate(2048)

pub_key = key.publickey().exportKey("PEM")
priv_key = key.exportKey("PEM")

#writing public key to file
pubKey = open('pubkey.pem', 'w')
pubKey.write(pub_key)
pubKey.close()

privKey = open('privkey.pem', 'w')
privKey.write(priv_key)
privKey.close()

