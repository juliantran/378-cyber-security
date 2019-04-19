import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as textPadding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

keyLen = 32
cbcLen = 16

def MyencryptHMAC(key, message, HMACKey):
    #returns error if the len(key) < 32 (256 bits)
    if len(key) < keyLen:
        print("The key must be 32 bytes.")
        return "Error"
    else:
        IV = os.urandom(cbcLen) #generates random 16 Bytes, to be used for CBC

        pad = textPadding.PKCS7(128).padder() #the padding to message if needed
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

    unpad = textPadding.PKCS7(128).unpadder() #the unpadder
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




#RSA encryption is interesting because encryption is performed using the public key, meaning anyone can encrypt data. 
def myRSAEncrypt(filepath, RSA_publickey_filepath):
    (encryptedMessage, IV, tag, key, HMACKey, file_ext) = MyfileEncryptHMAC(filepath)  #encrypting

    concatenated_Keys = key + HMACKey  #concatenate the encrypted key and the HMAC key

    #if the file exists then load the public key from the public key.pem file
    with open(RSA_publickey_filepath, "rb") as keyFile:
        publicKey = serialization.load_pem_public_key(  
            keyFile.read(),  #we read the pem file that holds our key
            backend=default_backend()
        )

    #using the RSA public key and the OAEP padding mode to encrypt the key, the result will be an RSA Cipher
    RSACipher = publicKey.encrypt(  #anyone can encrypt data so we use the public key to encrypt
        concatenated_Keys,  #will encrypt the concatenated key
        padding.OAEP( 
            #Valid paddings for encryption are OAEP and PKCS1v15. OAEP is the recommended choice for any new protocols 
            #or applications, by appling padding to our key using the OAEP interface padding scheme which will provide
            #probabilistic encryption
            
            #MGF1 (Mask Generation Function 1) is used as the mask generation function in PSS and OAEP padding 
            #It takes a hash algorithm in this case SHA256
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        #if no instance of an algorithm is passed into the OAEP interface a TypeError will be triggered, same applies to MGF1 padding
        #"Expected instance of hashes.HashAlgorithm"
    )

    return RSACipher, encryptedMessage, IV, tag, file_ext

#The data is then decrypted using the private key.
def myRSADecrypt(filepath, RSACipher, cipher_text, IV, tag, file_ext, RSA_privatekey_filepath):
    with open(RSA_privatekey_filepath, "rb") as key_file:  #open our private key PEM file for decrypting
        privateKey = serialization.load_pem_private_key(
            #load serialized private key that is stored in the PEM file
            key_file.read(),  #read private key
            password=None,  #private key was encrypted at serialization, so no password
            backend=default_backend()
        )

    concatenated_Keys_decrypted = privateKey.decrypt(  #decrypt the concatenated keys
        RSACipher,  #RSACipher needs to be decrypted so that we can get the EncKey and HMACKey
        padding.OAEP(  #unpad our padder which provided the probabilistic encryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            #unpad the mask generation function along with the SHA256 hash function
            algorithm=hashes.SHA256(),  #decrypt our OAEP RSACipher with the hash function SHA25
            label=None
        )
    )

    #split the concatenated key into two - EncKey and HMACKey
    EncKey = concatenated_Keys_decrypted[:32]
    HMACKey = concatenated_Keys_decrypted[32:64]

    #decrypt the message in our file path and return the data
    MyfileDecryptHMAC(IV, tag, EncKey, HMACKey, filepath)

#method will generate a serialized public and private key and then write them to a PEM file for each
def RSAKeyGen(RSA_publickey_filepath, RSA_privatekey_filepath):

    #return true if it exists, false if it does not
    existsPublic = os.path.isfile(RSA_publickey_filepath)
    existsPrivate = os.path.isfile(RSA_privatekey_filepath)
    
    #if the public or private key PEM filepaths do not exist in the directory then we generate
    #a new private key PEM file and a new public key PEM file
    if(existsPublic == False or existsPrivate == False):
        
        #generate a private key
        privateKey = rsa.generate_private_key(
                public_exponent=65537,
                #public_exponent (int) – The public exponent of the new key
                #prime number to use, if in doubt use 65537, the highest Fermat prime this is -
                #large enough to avoid the attacks to which small exponents make RSA vulnerable
                #can be computed extremely quickly on binary computers
                key_size=2048, 
                #key_size (int) – The length of the modulus in bits.
                backend=default_backend()
                )

        #generate a public key from the values in our private key
        publicKey = privateKey.public_key()

        #serializing the private key so that it can be encoded into bits and be transmitted
        #if you have a private key that you’ve loaded or generated which implements the 
        #RSAPrivateKeyWithSerialization interface you can use private_bytes() to serialize the key.
        prvKey = privateKey.private_bytes(  #using RSAPrivateKeyWithSerialization interface to serialize key
            encoding=serialization.Encoding.PEM,
            #encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #private key format for our key which includes the header and footer
            encryption_algorithm=serialization.NoEncryption()
            #encryption algorithm to be used for the serializtion, not used in our case using NoEncryption
        )
        
        #for public keys you can use public_bytes() to serialize the key
        #serializing the public key so that it can be encoded into bits and be transmitted
        pubKey = publicKey.public_bytes( #using the RSAPrivateKeyWithSerialization interface to serialize our public key
            encoding=serialization.Encoding.PEM, #encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PublicFormat.SubjectPublicKeyInfo #using the typical public key format for our public key
        )

        #generate a publicKey.pem file that will store our serialized public key
        file = open(RSA_publickey_filepath, 'wb')  #create publicKey.pem file
        file.write(pubKey)  #write our serialized public key to the PEM file
        file.close()  

        #generate a privateKey.pem file that will store our serialized private key
        file = open(RSA_privatekey_filepath, 'wb')  #create the privateKey.pem file
        file.write(prvKey)  #write our serialized private key to the PEM file
        file.close()

    #return the PEM filepaths for our public and private keys after being generated
    return RSA_publickey_filepath, RSA_privatekey_filepath


def main():
    
    filepath = "C:\\Users\\James\\Desktop\\School\\CECS 378\\testing folder\\999.jpg"
    
    RSA_publickey_filepath = 'C:\\Users\\James\\Desktop\\School\\CECS 378\\testing folder\\publicKey.pem'
    RSA_privatekey_filepath = 'C:\\Users\\James\\Desktop\\School\\CECS 378\\testing folder\\privateKey.pem'
    (RSA_publickey_filepath, RSA_privatekey_filepath) = RSAKeyGen(RSA_publickey_filepath, RSA_privatekey_filepath)


    (RSACipher, cipher_text, iv, tag, file_ext) = myRSAEncrypt(filepath, RSA_publickey_filepath)
    #(C, IV, tag, key, HMACkey, ext) = MyfileEncryptHMAC(filepath)
    pause = input() #just to pause for testing purposes
    #MyfileDecryptHMAC(IV, tag, key, HMACkey, filepath)
    
    myRSADecrypt(filepath, RSACipher, cipher_text, iv, tag, file_ext, RSA_privatekey_filepath)
    
main()