import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
#You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).
def Myencrypt(key, message):
    #returns error if the len(key) < 32 (256 bits)
    if len(key) < 32:
        print("The key must be 32 bytes.")
        return "Error"
    else:
        IV = os.urandom(16) #generates random 16 Bytes, to be used for CBC

        pad = padding.PKCS7(128).padder() #the padding to message if needed
        padData = pad.update(message) #padding the message if needed
        padData += pad.finalize() #can not update it again after finalizing, will throw an error
        #Finalize the current context and return the rest of the data.
        #After finalize has been called this object can no longer be used
        
        #encrypts the padded message using AES with key and IV in cipher block chaining mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
        encrypt = cipher.encryptor()
        encryptedMessage = encrypt.update(padData) + encrypt.finalize()

        return encryptedMessage, IV #return tuple

def Mydecrypt(key, IV, encryptedMessage):
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
    decrypt = cipher.decryptor()
    message = decrypt.update(encryptedMessage) + decrypt.finalize()

    unpad = padding.PKCS7(128).unpadder() #the unpadder
    decryptedMessage = unpad.update(message) #unpadding the message
    decryptedMessage += unpad.finalize()

    return decryptedMessage

#In this method, you'll generate a 32Byte key. You open and read the file as a string. 
#You then call the above method to encrypt your file using the key you generated. 
#You return the cipher C, IV, key and the extension of the file (as a string).
def MyfileEncrypt(filepath):
    
    key = os.urandom(32) #random key of 32 bytes for encryption to use
    #opens the file to read the data of the file
    file = open(filepath, "rb") #“rb” (read binary)
    message = file.read()
    file.close()

    (encryptedMessage, IV) = Myencrypt(key, message) #encrypt the message with the key
    
    #writes the encoded message back to the file
    file = open(filepath, "wb") #“wb” (write binary)
    file.write(encryptedMessage)
    file.close()
    
    fileExt = os.path.splitext(filepath)[1] # Grabs the file extension, not using yet, so another part of it
    
    return encryptedMessage, IV, key, fileExt #return tuple

def MyfileDecrypt(IV, key, filepath):
    
    file = open(filepath, "rb") #“rb” (read binary)
    encryptedMessage = file.read()
    file.close()
    
    message = Mydecrypt(key, IV, encryptedMessage)
    #writes the encoded ciphertext back to the original file
    file = open(filepath, "wb") #“wb” (write binary)
    file.write(message)
    file.close()

def main():
    
    filepath = "/Users/Julian/Documents/CECS378/enctext.txt" #testing txt file
    #filepath = "/Users/Julian/Documents/CECS378/encpicture.jpg" #testing jpg file
    
    (C, IV, key, ext) = MyfileEncrypt(filepath)
    pause = input() #just to pause for testing purposes
    MyfileDecrypt(IV, key, filepath)

main()
