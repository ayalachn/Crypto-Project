"""
This program implements the RSA algorithm for cryptography.
It randomly selects two prime numbers from a txt file of prime numbers and 
uses them to produce the public and private keys. Using the keys, it can 
either encrypt or decrypt messages.
"""

import random

class RSA:
    __p = None #first private prime number
    __q = None #second private prime number
    __e = 0 #public key
    __d = None #private key
    __n = None #public value
    
    # Returns the public modulos
    def getN(self):
        return self.__n
    
    # Returns the RSA's public key for encryption
    def getPublicKey(self):
        return self.__e
    
    #Performs the Euclidean algorithm and returns the gcd of a and b
    def gcd(self, a, b):
        if (b == 0):
            return a
        else:
            return self.gcd(b, a % b)

    #Performs the extended Euclidean algorithm. 
    #Returns the gcd, coefficient of a, and coefficient of b
    def xgcd(self, a, b):
        x, old_x = 0, 1
        y, old_y = 1, 0
    
        while (b != 0):
            quotient = a // b
            a, b = b, a - quotient * b
            old_x, x = x, old_x - quotient * x
            old_y, y = y, old_y - quotient * y
    
        return a, old_x, old_y
    

    #Choose public key e: Chooses a random number, 1 < e < totient, and checks whether or not 
    #it is coprime with the totient, that is, gcd(e, totient) = 1
    def chooseE(self, totient):
        while (True):
            self.__e = random.randrange(2, totient)
    
            if (self.gcd(self.__e, totient) == 1):
                return self.__e
            
    # ChooseKeys Func- Selects two random prime numbers from a list of prime 
    # numbers which has values that go up to 100k. It creates a text file and stores
    # the two numbers there where they can be used later. Using the prime numbers,
    # it also computes and stores the public and private keys in two separate files.
    def chooseKeys(self):
        
        # choose two random numbers within the range of lines in the txt file example
        rand1 = random.randint(100, 130) #ORIGIANL (100,300) ****************************************************************
        rand2 = random.randint(100, 130) #Note: we chose small values to make the program run faster. For real use, we choose
    
        # store the txt file of prime numbers in a python list
        fo = open('RSA_/primes-to-100k.txt', 'r')
        lines = fo.read().splitlines()
        fo.close()
    
        # store our prime numbers in these variables
        prime1 = int(lines[rand1])
        prime2 = int(lines[rand2])
        self.__p = prime1
        self.__q = prime2
    
        # compute n, totient, e
        self.__n = prime1 * prime2 # n=pq
        totient = (prime1 - 1) * (prime2 - 1) # phi(n) = (p-1)(q-1)
        self.__e = self.chooseE(totient) #Choose e that fits the terms
    
        # compute d, 1 < d < totient such that ed = 1 (mod totient)
        # e and d are inverses (mod totient)
        gcd, x, y = self.xgcd(self.__e, totient)
    
        # make sure d is positive
        if (x < 0):
            self.__d = x + totient
        else:
            self.__d = x
        
        
        # The keys are saved in txt files. There is a file for the public keys and for the private keys
        # write the public keys n and e to a file
        f_public = open('public_keys.txt', 'w')
        f_public.write(str(self.__n) + '\n')
        f_public.write(str(self.__e) + '\n')
        f_public.close()
    
        f_private = open('private_keys.txt', 'w')
        f_private.write(str(self.__n) + '\n')
        f_private.write(str(self.__d) + '\n')
        f_private.close()
    
    
    # encrypt func- Encrypts a message (string) by raising each character's ASCII value
    # to the power of e and taking the modulus of n. Returns a string of numbers.
    # file_name refers to file where the public key is located. If a file is not 
    # provided, it assumes that we are encrypting the message using our own 
    # public keys. Otherwise, it can use someone else's public key, which is 
    # stored in a different file.
    # block_size refers to how many characters make up one group of numbers in 
    # each index of encrypted_blocks.
    def encrypt(self, message, file_name = 'public_keys.txt', block_size = 2):
    
        # check for the possibility that the user tries to encrypt something
        # using a public key that is not found
        try:
            fo = open(file_name, 'r')
            
        except FileNotFoundError:
            print('That file is not found.')
        else:
            self.__n = int(fo.readline()) #read n value from public key txt file
            self.__e = int(fo.readline()) #read e value from public key txt file
            fo.close() #close public key txt file
    
            encrypted_blocks = []
            ciphertext = -1
    
            if (len(message) > 0):
                # initialize ciphertext to the ASCII of the first character of message
                ciphertext = ord(message[0])
    
            for i in range(1, len(message)):
                # add ciphertext to the list if the max block size is reached
                # reset ciphertext so we can continue adding ASCII codes
                if (i % block_size == 0):
                    encrypted_blocks.append(ciphertext)
                    ciphertext = 0
    
                # multiply by 1000 to shift the digits over to the left by 3 places
                # because ASCII codes are a max of 3 digits in decimal
                ciphertext = ciphertext * 1000 + ord(message[i])
    
            # add the last block to the list
            encrypted_blocks.append(ciphertext)
    
            # encrypt all of the numbers by taking it to the power of e
            # and modding it by n
            for i in range(len(encrypted_blocks)):
                encrypted_blocks[i] = str((encrypted_blocks[i]**self.__e) % self.__n)
    
            # create a string from the numbers
            encrypted_message = " ".join(encrypted_blocks)
    
            return encrypted_message
        
    # Decrypts a string of numbers by raising each number to the power of d and 
    # taking the modulus of n. Returns the message as a string.
    # block_size refers to how many characters make up one group of numbers in
    # each index of blocks.
    def decrypt(self, blocks, block_size = 2):
    
        fo = open('private_keys.txt', 'r')
        self.__n = int(fo.readline()) #read n value from private key txt file
        self.__d = int(fo.readline()) #read d value from private key txt file
        fo.close() #close private keys file
    
        # turns the string into a list of ints
        list_blocks = blocks.split(' ')
        int_blocks = []
    
        for s in list_blocks:
            int_blocks.append(int(s))
    
        message = ""
    
        # converts each int in the list to block_size number of characters
        # by default, each int represents two characters
        for i in range(len(int_blocks)):
            # decrypt all of the numbers by taking it to the power of d
            # and modding it by n
            int_blocks[i] = (int_blocks[i]**self.__d) % self.__n
            
            tmp = ""
            # take apart each block into its ASCII codes for each character
            # and store it in the message string
            for c in range(block_size):
                tmp = chr(int_blocks[i] % 1000) + tmp
                int_blocks[i] //= 1000
            message += tmp
    
        return message
    
# Main for checking RSA
"""
def main():
    # we select our primes and generate our public and private keys,
    # usually done once
    choose_again = input('Do you want to generate new public and private keys? (y or n) ')
    if (choose_again == 'y'):
        chooseKeys()

    instruction = input('Would you like to encrypt or decrypt? (Enter e or d): ')
    if (instruction == 'e'):
        message = input('What would you like to encrypt?\n')
        option = input('Do you want to encrypt using your own public key? (y or n) ')

        if (option == 'y'):
            print('Encrypting...')
            print(encrypt(message))
        else:
            file_option = input('Enter the file name that stores the public key: ')
            print('Encrypting...')
            print(encrypt(message, file_option))

    elif (instruction == 'd'):
        message = input('What would you like to decrypt?\n')
        print('Decryption...')
        print(decrypt(message))
    else:
        print('That is not a proper instruction.')

main()
"""