# -*- coding: utf-8 -*-
"""
Created on Fri Dec 10 18:25:46 2021

"""

import XTEA.xtea as XTEA
import SHA256.sha256 as SHA256
from RSA_.rsa import RSA
import ElGamalEcc.ElGamalEcc as elgamal
import os
import binascii

#Alice
class Sender:
    # sender's plain text:
    msg =""

    # RSA:
    RsaE = None # RSA public encryption key
    RsaN = None # RSA n public modolus
    rsa = RSA() # instance of RSA class
    
    # XTEA:
    XTEA_key = os.urandom(16)   # generate secret symmetric key for XTEA
    print("THE XTEA KEY IS: (GENERATED)")
    print(XTEA_key)
    XTEA_iv = os.urandom(8)     # generate IV for XTEA
    XTEA_Encryptor = XTEA.XTEACipher(key=XTEA_key, IV=XTEA_iv, mode=XTEA.MODE_OFB, segment_size=64)
    XTEA_encryptedKey=None
    
    # EL-GAMAL ON EC:
    ElGamal = elgamal.ElGamalEcc(23) # Sender's El-Gamal secret key is 23.
    
    # set sender's plain text - this text will be encrypted using XTEA on OFB and 
    # signed using El-Gamal on ECC.
    def setMessage(self, msg):
        self.msg=msg
                    
    # receive public RSA key for encryption and RSA's n modolous
    def setRsaPublicKey(self, RsaE, RsaN):
        self.RsaE, self.RsaN = RsaE, RsaN
    
    # encrypts XTEA secret symmetric key.
    # returns the encrypted XTEA key and its digital signature.
    def getEncryptedXTEAKey(self):
        # encrypt XTEAKey using bob's RSA public key e and public modolus n
        print("XTEA KEY AFTER HEXLIFY:\n", str(binascii.hexlify(self.XTEA_key).decode("utf-8")))
        self.XTEA_encryptedKey = self.rsa.encrypt(message=str(binascii.hexlify(self.XTEA_key).decode("utf-8")), file_name = 'public_keys.txt', block_size = 2) # change this to variables? 

        print("RSA RETURN VAL:")
        print(self.XTEA_encryptedKey)
        
        # generate digital signature to the hashed XTEA key using El-Gamal on EC
        r,s = self.digitalSignMessage(str(binascii.hexlify(self.XTEA_key).decode("utf-8")))

        return self.XTEA_encryptedKey, self.XTEA_iv, r, s # return encrypted key with digital signature {r, s}
    
    # generates digital signature {r, s} using El-Gamal algorithm on Elliptic Curves
    def digitalSignMessage(self, message):
        print("ALICE signs ", message)
        r, s = self.ElGamal.digitalSignMessage(message)
        return r, s 
    
    # Returns:
    # cipherText: encrypted message (via XTEA on OFB algorithm)
    # XTEA_iv: XTEA's public initial vector
    # {r, s}: message's digital signature (via El-Gamal on EC)   
    def getEncryptMessage(self):
       # encrypt plain text via XTEA on OFB
       cipherText =  self.XTEA_Encryptor.encrypt(self.msg)
       
       # digital sign message (via El-Gamal on EC)
       r, s = self.digitalSignMessage(self.msg)
       
       return cipherText, r, s
#Bob  
class Receiver:
    # RSA:
    RsaPrivateKey = None
    RsaN = None 
    rsa = RSA()
    
    # EL-GAMAL ON EC:
    ElGamal = elgamal.ElGamalEcc(17) # Receiver's El-Gamal secret key is 17.  
    
    # XTEA:
    XTEA_key=None
    XTEA_Encryptor = None
    
    # Returns public key for RSA encryption: {e, n}
    def getRsaPublicKey(self):
        self.rsa.chooseKeys() # ************ sign public key?
        return self.rsa.getPublicKey(), self.rsa.getN()
    
    # deciphers encrypted XTEA key (via RSA) and validates it by its
    # digital signature {r, s}
    def setXTEAKey(self, encryptedXTEAkey, XTEA_iv, r, s):
        # decrypt using RSA
        print("the key to decrypt in rsa is:")
        print(encryptedXTEAkey)
        self.XTEA_key = self.rsa.decrypt(encryptedXTEAkey, block_size = 2)
        
        print("XTEA key decrypted utf-8: ", binascii.unhexlify(self.XTEA_key))
        self.XTEA_Encryptor = XTEA.XTEACipher(key=binascii.unhexlify(self.XTEA_key), IV=XTEA_iv, mode=XTEA.MODE_OFB, segment_size=64)
        
        print("VERIFY: ", self.XTEA_key)
        # self.XTEA_Encryptor = XTEA.XTEACipher(key=bytes(self.XTEA_key, 'utf-8'), IV=XTEA_iv, mode=XTEA.MODE_OFB, segment_size=64)
        # authenticate message using El-Gamal on EC
        if not self.ElGamal.verifyDigitalSignature(m=self.XTEA_key, r=r, s=s):
            print("Signature of XTEA key was that sent by Sender is invalid.") # add here a chance to fix the situation?
            return False
        return True # signature is valid
    
    # decypher input cipher text (via XTEA on OFB) and validate
    # its digital signature {r, s}. Returns decrypted plain text.
    def decryptCipherMsg(self, cipherText, r, s):
        # decrypt cipher text using XTEA on OFB
        plainText = self.XTEA_Encryptor.decrypt(cipherText).decode('utf-8')
        print("BOB XTEA DECRYPT: ",plainText)
        # validate digital signature of message
        if not self.ElGamal.verifyDigitalSignature(m=plainText, r=r, s=s):
            print("Signature of messsage from Sender is invalid.") # add here a chance to fix the situation?
            return None
        return plainText
    
    
alice = Sender()
bob = Receiver()
alice.ElGamal.setOthersPublicKey(bob.ElGamal.getMyPublicKey())
bob.ElGamal.setOthersPublicKey(alice.ElGamal.getMyPublicKey())

RsaE, RsaN = bob.getRsaPublicKey()
alice.setRsaPublicKey(RsaE, RsaN)
a,b,c,d = alice.getEncryptedXTEAKey() #CHANGE VARS NAME ****
bob.setXTEAKey(a,b,c,d)

# # both parties hold the secret key for the symmetric algorithm - 
# # we can now send the message from alice to bob using XTEA (the symmetric algorithm)
alicePlainText = "Hello"
print("Alice wants to encrypt: ", alicePlainText)
alice.setMessage(alicePlainText) # alice sets plain text to encrypt and send to bob
cipherText, r, s=alice.getEncryptMessage()
bobPlainText=bob.decryptCipherMsg(cipherText, r, s)
print("Bob's decrypted text: ", bobPlainText)

# Algorithm check
if bobPlainText != alicePlainText:
    print("Decryption unsuccessful")
else:
    print("Decryption successful")  