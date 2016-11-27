from message import Message
import base64
from time import sleep
from threading import Thread
from AESCipher import *
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
import binascii
import datetime

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''
        # You can use this function to initiate your key exchange
		# Useful stuff that you may need:
		# - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_user()
        # You may need to send some init message from this point of your code
		# you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
		# replace this with anything needed for your key exchange 
        pass


    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        # process message here
        # example is base64 decoding, extend this with any crypto processing of your protocol
        decoded_msg = base64.decodestring(msg_raw)

        f = open(str(self.get_id()) + 'Key.txt', 'r')
        group_key = binascii.hexlify(f.read())
        f.close()

        # last 32 bytes should be the signature
        encr_msg = decoded_msg
        print 'decoded message len'
        print len(encr_msg)
        #encr_msg = decoded_msg[:-256]
        #signature = decoded_msg[-256:]

        #print signature
        '''
        key = RSA.importKey(open(owner_str.lower() + 'PubKey.pem').read())
        h = SHA256.new()
        h.update(encr_msg)
        verifier = PKCS1_PSS.new(key)
        
        if not verifier.verify(h,signature):
            raise Exception('Signature not valid')
        '''

        aes_group = AESCipher(group_key)
        # get message key
        encr_message_key = encr_msg[:32]
        print 'enc mess'
        print encr_message_key
        message_key = aes_group.decrypt(encr_message_key)
        print 'message key'
        print message_key

        # decrypt message using message key
        encr_message = encr_msg[32:]
        message_cipher = AESCipher(message_key)
        decoded_msg = message_cipher.decrypt(encr_message)

        # print message and add it to the list of printed messages
        self.print_message(
            msg_raw=decoded_msg,
            owner_str=owner_str
        )

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        # process outgoing message here
        f = open(str(self.get_id()) + 'Key.txt', 'r')
        group_key = binascii.hexlify(f.read())
        f.close()
        aes_group = AESCipher(group_key)

        # generate message key
        message_key = binascii.hexlify(generateKey())
        aes_message = AESCipher(message_key)

        # encrypt message key using group key
        e_message_key = aes_group.encrypt(message_key)

        #add timestamp to message
        message = msg_raw + str(datetime.datetime.utcnow())

        # encrypt message with message key
        e_message = aes_message.encrypt(message)
        '''
        # get private key
        owner = str(self.manager.user_name).lower()
        key = RSA.importKey(open(owner + "PrivKey.pem").read())
        h = SHA256.new()
        h.update(e_message)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)
        '''
        #print signature

        encrypted_data = str(e_message_key) + str(e_message)# + str(signature)
        print "Encrypted data length"
        print len(encrypted_data)

        # example is base64 encoding, extend this with any crypto processing of your protocol
        encoded_msg = base64.encodestring(encrypted_data)
        
        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)
