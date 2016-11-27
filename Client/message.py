from user import User
from json import JSONEncoder
from AESCipher import *
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
import datetime
import urllib2
import json
from config import *
import binascii
import base64

class Message():
    '''
    Represents a single message in a conversation
    '''

    def __init__(self, owner_name="", content="", group_id=0):
        '''
        Constructor
        :param owner_name: user name of the user who created the message
        :param content: the raw message as a string
        :return: instance
        '''
        self.content = content
        self.owner = User(owner_name)
        self.group_id = group_id

    def __str__(self):
        '''
        Called when the message is printed with the print or str() instructions
        :return: string
        '''
        return str(self.owner) + " " + self.content + "\n"

    def __eq__(self, other):
        assert isinstance(other, Message)
        return (self.content == other.content) and (self.owner.get_user_name() == other.owner.get_user_name())

    def __ne__(self, other):
        assert isinstance(other, Message)
        return not (self == other)

    def get_owner(self):
        '''
        Returns the user name of the user who created the message
        :return: string
        '''
        return self.owner

    def get_content(self):
        '''
        Returns the raw message contents
        :return: string
        '''
        return self.content
    
    def get_group_id(self):
        '''
        Returns the group_id
        '''
        return self.group_id

class MessageEncoder(JSONEncoder):
    '''
    Class responsible for JSON encoding instances of the Message class
    '''
    def default(self, o):
        '''
        Does the encoding
        :param o: should be an instance of the Message class
        :return: dict that can be serialized into JSON
        '''
        
        assert isinstance(o, Message)

        f = open(str(o.get_group_id()) + 'Key.txt', 'r')
        group_key = binascii.hexlify(f.read())
        f.close()
        aes_group = AESCipher(group_key)

        # generate message key
        message_key = binascii.hexlify(generateKey())
        aes_message = AESCipher(message_key)

        # encrypt message key using group key
        e_message_key = aes_group.encrypt(message_key)

        # add timestamp to message
        message = o.get_content() + str(datetime.datetime.utcnow())

        # encrypt message with message key
        e_message = aes_message.encrypt(message)

        # get private key
        owner = str(o.get_owner()).lower()
        key = RSA.importKey(open(owner[2:-1] + "PrivKey.pem").read())
        h = SHA256.new()
        h.update(e_message)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)

        print len(signature)

        encrypted_data = str(e_message_key) + str(signature)
        encode = base64.encodestring(encrypted_data)
        return {"content" : encode}
