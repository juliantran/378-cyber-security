import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac

keyLen = 32
cbcLen = 16

def MyencryptHMAC(key, message, HMACKey):
    #returns error if the len(key) < 32 (256 bits)
    if len(key) < keyLen:
        print("The key must be 32 bytes.")
        return "Error"
    else:
        IV = os.urandom(cbcLen) #generates random 16 Bytes, to be used for CBC

        pad = padding.PKCS7(128).padder() #the padding to message if needed
        padData = pad.update(message) #padding the message if needed
        padData += pad.finalize() #can not update it again after finalizing, will throw an error
        
        #encrypts the padded message using AES with key and IV in cipher block chaining mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
        encrypt = cipher.encryptor()
        encryptedMessage = encrypt.update(padData) + encrypt.finalize()
        
        # Creates a HMAC tag
        hmacTag = hmac.HMAC(HMACKey, hashes.SHA256(), default_backend()) #creating the HMAC tag
        hmacTag.update(encryptedMessage) #will hash and authenticate the bytes of the encrypted message
        hmacTag = hmacTag.finalize() #finalizing the tag of the encrypted message, only needs to return the tag

        return encryptedMessage, IV, hmacTag #return tuple

def MydecryptHMAC(key, IV, encryptedMessage, hmacKey, tag):
    
    # Creates a HMAC tag
    hmacTag = hmac.HMAC(hmacKey, hashes.SHA256(), default_backend()) #SHA3_256
    hmacTag.update(encryptedMessage)

    hmacTag.verify(tag) # Verifies if the received tag matches the one created
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
    decrypt = cipher.decryptor()
    message = decrypt.update(encryptedMessage) + decrypt.finalize()#needed to add the padding to the rest of the message because
                                                                    #the padding is anthor block that can be encrypted
                                                                    #and added to it, then finalize it

    unpad = padding.PKCS7(128).unpadder() #the unpadder
    decryptedMessage = unpad.update(message) #unpadding the message
    decryptedMessage += unpad.finalize()

    return decryptedMessage

def MyfileEncryptHMAC(filepath):
    
    key = os.urandom(keyLen) #random key of 32 bytes for encryption to use
    HMACKey = os.urandom(keyLen)
    
    #opens the file to read the data of the file
    file = open(filepath, "rb") #rb reads by binary
    message = file.read()
    file.close()

    (encryptedMessage, IV, tag) = MyencryptHMAC(key, message, HMACKey) #encrypt the message with the key
    
    #writes the encoded message back to the file
    file = open(filepath, "wb") #wb writes by binary 
    file.write(encryptedMessage)
    file.close()
    
    fileExt = os.path.splitext(filepath)[1] # Grabs the file extension, not using yet, so another part of it
    
    return encryptedMessage, IV, tag, key, HMACKey, fileExt #return tuple

def MyfileDecryptHMAC(IV, tag, key, HMACKey, filepath):
    
    file = open(filepath, "rb") #rb reads by binary
    encryptedMessage = file.read()
    file.close()
    
    message = MydecryptHMAC(key, IV, encryptedMessage, HMACKey, tag)
    #writes the encoded ciphertext back to the original file
    file = open(filepath, "wb")
    file.write(message)
    file.close()



def main():
    
    #filepath = "C:\\Users\\James\\Desktop\\testing folder\\99.txt"
    filepath = "C:\\Users\\James\\Desktop\\School\\CECS 378\\testing folder\\999.jpg"
    
    (C, IV, tag, key, HMACkey, ext) = MyfileEncryptHMAC(filepath)
    pause = input() #just to pause for testing purposes
    MyfileDecryptHMAC(IV, tag, key, HMACkey, filepath)

main()