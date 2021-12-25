# -*- coding: utf-8 -*-
"""
Created on Fri Dec 10 18:25:46 2021

"""

import XTEA.xtea as XTEA
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
    rsa = RSA() # Instance of RSA class
    
    # XTEA:
    XTEA_key = os.urandom(16)   # Generate secret symmetric key for XTEA
    XTEA_iv = None
    
    XTEA_encryptedKey=None
    
    # EL-GAMAL ON EC:
    ElGamal = elgamal.ElGamalEcc(23) # Sender's El-Gamal secret key is 23 (chosen randomly from the interval: [1, n-1]).
    
    # Set sender's plain text - this text will be encrypted using XTEA on OFB and 
    # signed using El-Gamal on ECC.
    def setMessage(self, msg):
        self.msg=msg
        self.XTEA_iv = os.urandom(8) # Generate IV for XTEA
                    
    # Receive public RSA key for encryption and RSA's n modulo
    def setRsaPublicKey(self, RsaE, RsaN):
        self.RsaE, self.RsaN = RsaE, RsaN
    
    # Encrypts XTEA secret symmetric key.
    # Returns the encrypted XTEA key and its digital signature.
    def getEncryptedXTEAKey(self):
        # Encrypt XTEAKey using bob's RSA public key e and public modolus n
        self.XTEA_encryptedKey = self.rsa.encrypt(message=str(binascii.hexlify(self.XTEA_key).decode("utf-8")), file_name = 'public_keys.txt', block_size = 2)

        # Generate digital signature to the hashed XTEA key using El-Gamal on EC
        r,s = self.digitalSignMessage(str(binascii.hexlify(self.XTEA_key).decode("utf-8")))

        return self.XTEA_encryptedKey, self.XTEA_iv, r, s # return encrypted key with digital signature {r, s}
    
    # generates digital signature {r, s} using El-Gamal algorithm on Elliptic Curves
    def digitalSignMessage(self, message):
        r, s = self.ElGamal.digitalSignMessage(message)
        return r, s 
    
    def getIV(self):
        return self.XTEA_iv
    # Returns:
    # cipherText: encrypted message (via XTEA on OFB algorithm)
    # XTEA_iv: XTEA's public initial vector
    # {r, s}: message's digital signature (via El-Gamal on EC)   
    def getEncryptMessage(self):
       # Encrypt plain text via XTEA on OFB
       XTEA_Encryptor = XTEA.XTEACipher(key=self.XTEA_key, IV=self.XTEA_iv, mode=XTEA.MODE_OFB, segment_size=64)

       cipherText =  XTEA_Encryptor.encrypt(self.msg)
       
       # Digital sign message (via El-Gamal on EC)
       r, s = self.digitalSignMessage(self.msg)
       
       return cipherText, r, s
#Bob  
class Receiver:
    # RSA:
    RsaPrivateKey = None
    RsaN = None 
    rsa = RSA()
    
    # EL-GAMAL ON EC:
    ElGamal = elgamal.ElGamalEcc(17) # Receiver's El-Gamal secret key is 17 (chosen randomly from the interval: [1, n-1]).
    
    # XTEA:
    XTEA_key=None
    XTEA_Encryptor = None
    
    # Returns public key for RSA encryption: {e, n}
    def getRsaPublicKey(self):
        self.rsa.chooseKeys()
        return self.rsa.getPublicKey(), self.rsa.getN()
    
    # Deciphers encrypted XTEA key (via RSA) and validates it by its
    # digital signature {r, s}
    def setXTEAKey(self, encryptedXTEAkey, XTEA_iv, r, s):
        # Decrypt using RSA
        self.XTEA_key = self.rsa.decrypt(encryptedXTEAkey, block_size = 2)
        
        self.XTEA_Encryptor = XTEA.XTEACipher(key=binascii.unhexlify(self.XTEA_key), IV=XTEA_iv, mode=XTEA.MODE_OFB, segment_size=64)
        
        # Authenticate message using El-Gamal on EC
        if not self.ElGamal.verifyDigitalSignature(m=self.XTEA_key, r=r, s=s):
            print("Signature of XTEA key that was sent by Sender is invalid.")
            return False
        return True # Signature is valid
    
    # Decypher input cipher text (via XTEA on OFB) and validate
    # its digital signature {r, s}. Returns decrypted plain text.
    def decryptCipherMsg(self, cipherText, r, s):
        # Decrypt cipher text using XTEA on OFB
        plainText = self.XTEA_Encryptor.decrypt(cipherText).decode('utf-8')
        # Validate digital signature of message
        if not self.ElGamal.verifyDigitalSignature(m=plainText, r=r, s=s):
            print("Signature of messsage from Sender is invalid.")
            return None
        return plainText
    
    def setIV(self, IV): # If this is not the first message to decrypt
      self.XTEA_Encryptor = XTEA.XTEACipher(key=binascii.unhexlify(self.XTEA_key), IV=IV, mode=XTEA.MODE_OFB, segment_size=64)

    
    
alice = Sender()
bob = Receiver()
alice.ElGamal.setOthersPublicKey(bob.ElGamal.getMyPublicKey())
bob.ElGamal.setOthersPublicKey(alice.ElGamal.getMyPublicKey())

RsaE, RsaN = bob.getRsaPublicKey()
alice.setRsaPublicKey(RsaE, RsaN)

alicePlainText = "\nDear Bob,\nIt was nice seeing you at the party last night!\nHope to meet you again soon,\nAlice\n"
print("\nAlice's message to Bob before encryption:\n", alicePlainText)

alice.setMessage(alicePlainText) # Alice sets plain text to encrypt and sends to Bob
encrypted_key,iv,R,s = alice.getEncryptedXTEAKey()
bob.setXTEAKey(encrypted_key,iv,R,s)

# Both parties hold the secret key for the symmetric algorithm - 
# we can now send the message from Alice to Bob using XTEA (the symmetric algorithm)
cipherText, r, s=alice.getEncryptMessage()
print("\nSending to Bob...\n");
bobPlainText=bob.decryptCipherMsg(cipherText, r, s)
print("\nBob's received message after decryption:\n", bobPlainText)

# Algorithm check
if bobPlainText != alicePlainText:
    print("Decryption was unsuccessful.\n")
else:
    print("Decryption was successful.\n")  
    
# A second message from Alice to Bob to demonstrate choosing a random IV for XTEA
alicePlainText = "\nDear Bob,\nThank you for the flowers.\nHope to see you again tomorrow,\nAlice\n"
print("Alice's message to Bob before encryption:\n", alicePlainText)
alice.setMessage(alicePlainText) # Alice sets plain text to encrypt and send to bob
cipherText, r, s=alice.getEncryptMessage()
print("\nSending to Bob...\n");
bob.setIV(alice.getIV())
bobPlainText=bob.decryptCipherMsg(cipherText, r, s)
print("\nBob's received message after decryption:\n", bobPlainText)

# Algorithm check
if bobPlainText != alicePlainText:
    print("Decryption was unsuccessful.")
else:
    print("Decryption was successful.")      