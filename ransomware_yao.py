#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  7 09:55:21 2018

@author: flo
"""
import os, const, json, base64
from   cryptography.hazmat.primitives.asymmetric import rsa
from   cryptography.hazmat.primitives.asymmetric import padding as rsa_pad
from   cryptography.hazmat.primitives.ciphers    import Cipher, algorithms, modes
from   cryptography.hazmat.primitives            import padding, hashes, hmac, serialization
from   cryptography.hazmat.backends              import default_backend

#####################################################################################################################################################################
#Function    : generate_keys()
#Input(s)    : public key file path, private key file path
#Output(s)   : public key file path, private key file path
#Description : Looks for a public key given the filepath, if it doesn't exist, create key pairs in the given root

def generate_keys(pubkey_filepath, privkey_filepath):
    exists = os.path.isfile(pubkey_filepath)
    
    if not exists:
        print("generate_keys() Key pairs do not exist - generating...")
        
        pubkey_filename = os.path.basename(pubkey_filepath)
        privkey_filename = os.path.basename(privkey_filepath)
        
        print("generate_keys() pubfile: ",pubkey_filename)
        print("generate_keys() privfile: ",privkey_filename)
    
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        
        with open(privkey_filepath, 'wb') as priv_pem_file:
            priv_pem_file.write(private_key.private_bytes( encoding=serialization.Encoding.PEM, 
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm = serialization.NoEncryption()))
            
        with open(pubkey_filepath, 'wb') as pub_pem_file:
            pub_pem_file.write(public_key.public_bytes( encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))    
    else:
        print("Key Pairs exist")
            
    return pubkey_filepath, privkey_filepath

#####################################################################################################################################################################
#Function    : my_encrypt_hmac()
#Input(s)    : plain text message, encoding key, integrity key
#Output(s)   : cipher text, initialization vector, hmac tag
#Description : pads message using PKCS7 padder, generates a random IV, uses AES to encrypt the message in CBC mode, generates a tag for integrity hashing with SHA256.
    
def my_encrypt_hmac(message, enc_key, hmac_key):
    if(len(enc_key) < const.KEY_LENGTH):
        print("Error: Key must be 128 bytes")
        return -1
    
    #pad message
    padder     = padding.PKCS7(const.BLOCK_SIZE).padder()
    padded_msg = padder.update(message) + padder.finalize()
    
    #generate IV
    IV = os.urandom(const.IV_LENGTH)            
    
    #create cipher with key + IV
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_msg) + encryptor.finalize()
    
    #create tag
    hmac_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend()) 
    hmac_tag.update(cipher_text) #hashes the cipher_text                        # M ( Ko || M ) ( Ki || M )
    
    return cipher_text, IV, hmac_tag.finalize()
 
#####################################################################################################################################################################    
#Function    : my_decrypt_hmac()
#Input(s)    : cipher text, initialization vector, encoding key, integrity key, hmac tag
#Output(s)   : plain text message
#Description : verifies tag, use AES to decode in CBC mode, unpad the result
    
def my_decrypt_hmac(cipher_text, IV, enc_key, hmac_key, hmac_tag):
    decrypt_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    decrypt_tag.update(cipher_text)
    
    #check if cipher is good
    decrypt_tag.verify(hmac_tag)
    
    #create cipher with key + IV
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    cipher_text = decryptor.update(cipher_text) + decryptor.finalize()
    
    #unpad
    unpadder = padding.PKCS7(const.BLOCK_SIZE).unpadder()
    plain_text = unpadder.update(cipher_text) + unpadder.finalize() 

    return plain_text

#####################################################################################################################################################################
#Function    : file_encrypt_hmac()
#Input(s)    : 
#Output(s)   : 
#Description : 
    
def file_encrypt_hmac(filepath):
    file_name = os.path.basename(filepath)
    name,ext = os.path.splitext(file_name)
    enc_key  = os.urandom(const.KEY_LENGTH) 
    hmac_key = os.urandom(const.KEY_LENGTH) 

    
    print("file_encrypt_hmac() file_name = ",file_name)
        
    with open(filepath, "rb") as f:
        file_in = f.read()
        
    #print("file_encrypt_hmac() file_in = ",file_in)

    C, IV, tag = my_encrypt_hmac(file_in , enc_key, hmac_key)
    
    #print("file_encrypt_hmac() C = ",C)
    
    with open(filepath, "wb") as f:
        f.write(C)
    
    #print("file_encrypt_hmac() just wrote back to file")
    
    return C, IV, tag, enc_key, hmac_key, ext.encode()

#####################################################################################################################################################################
#Function    : file_decrypt_hmac()
#Input(s)    : 
#Output(s)   : 
#Description : 
    
def file_decrypt_hmac(filepath, C, IV, enc_key, hmac_key, tag):

    M = my_decrypt_hmac(C, IV, enc_key, hmac_key, tag)

    with open(filepath, "wb") as f:
        #print("file decrypt: writing back to file")
        f.write(M)
    
    return M

#####################################################################################################################################################################
#Function    : my_RSA_encrypt()
#Input(s)    : 
#Output(s)   : 
#Description : 
    
def my_RSA_encrypt(filepath, rsa_publickey_filepath):
    C, IV, tag, enc_key, hmac_key, ext = file_encrypt_hmac(filepath)

    with open(rsa_publickey_filepath, 'rb') as pub_pem_file:
        public_key = serialization.load_pem_public_key(pub_pem_file.read(),
                                                       backend=default_backend())
        
    rsa_cipher = public_key.encrypt(enc_key+hmac_key,
                                    rsa_pad.OAEP(mgf=rsa_pad.MGF1(algorithm=hashes.SHA256()), 
                                                 algorithm=hashes.SHA256(), 
                                                 label=None))
    return rsa_cipher, C, IV, tag, ext

#####################################################################################################################################################################
#Function    : my_RSA_decrypt()
#Input(s)    : 
#Output(s)   : 
#Description : 

def my_RSA_decrypt(filepath, rsa_cipher, C, IV, hmac_tag, ext, rsa_privatekey_filepath):
    print("my RSA decrypt: filepath =", filepath)
    with open(rsa_privatekey_filepath, 'rb') as priv_pem_file:
        private_key = serialization.load_pem_private_key(priv_pem_file.read(),
                                                         password=None,
                                                         backend=default_backend())
        
    dec_keys = private_key.decrypt(rsa_cipher, rsa_pad.OAEP(mgf=rsa_pad.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None))
    dec_enc_key = dec_keys[:const.KEY_LENGTH]
    dec_hmac_key = dec_keys[const.KEY_LENGTH:]
    
    M = file_decrypt_hmac(filepath, C, IV, dec_enc_key, dec_hmac_key, hmac_tag)
    
    return M

#####################################################################################################################################################################
#Function    : encrypt_all
#Input(s)    : 
#Output(s)   : 
#Description : 
    
def encrypt_all(directory, rsa_publickey_filepath):
    file_count = 0

    #every subdir needs to be looped through 
    for root, subdir_list, file_list in os.walk(directory):
        if directory is root:       
            for file_name in file_list:
                if not file_name.endswith(".pem") and not file_name.endswith(".py") and not file_name.endswith(".spec") and not file_name.endswith(".DS_Store"):
                    in_filepath = root + '/' + file_name
                    print("encrypt_all() filepath",in_filepath)
            
                    rsa_cipher, C, IV, tag, ext = my_RSA_encrypt(in_filepath, rsa_publickey_filepath)
                    #print("\nencrypt_all() rsa cipher: ", rsa_cipher)
                    #print("\nencrypt_all() C: ", C)
                    #print("\nencrypt_all() tag: ", tag)
                    #print("\nencrypt all() IV ", IV)
                
                    ascii_rsa = base64.encodebytes(rsa_cipher).decode('ascii')
                    ascii_C   = base64.encodebytes(C).decode('ascii')
                    ascii_tag = base64.encodebytes(tag).decode('ascii')
                    ascii_iv  = base64.encodebytes(IV).decode('ascii')
                    ascii_ext = base64.encodebytes(ext).decode('ascii')
                    #JSON only supports unicode strings. Since Base64 encodes bytes to ASCII-only bytes, you can use that codec to decode the data
            
                    #json_obj = {"RSA":json_rsa, "C":json_c, "Tag":json_tag, "IV":json_iv, "Ext":json_ext}
                    json_file = json.dumps({"RSA":ascii_rsa, "C":ascii_C, "Tag":ascii_tag, "IV":ascii_iv, "Ext":ascii_ext})
                    #print("\nencrypt_all() json data = ",json_file)
                    
                    out_filepath = root+"/"+str(file_count)+"ENCRYPTED.json"
                    file_count += 1
                    
                    #print("encrypt_all() json path",out_path)
                    
                    #write json_object to file
                    json_out = open(out_filepath, "w") #write
                    json_out.write(json_file)
                    json_out.close()
            
                    #delete plaintext
                    os.remove(in_filepath)   
                    
                    #print("encrypt_all() os.removed: ",in_file_path)
        
#####################################################################################################################################################################
#Function    : decrypt_all()
#Input(s)    : 
#Output(s)   : 
#Description :       
                    
def decrypt_all(directory, rsa_privatekey_filepath):
    file_count = 0
    
    for root, subdir_list, file_list in os.walk(directory):
        if directory is root:
            for file_name in file_list:
                if file_name.endswith(".json"):
                    #print("decrypt_all() file:", file_name)
                    
                    in_filepath = root + '/' + file_name
                    
                    print("decrypt_all() file_path",in_filepath)
                    
                    with open(in_filepath, 'r') as f:
                        json_data = f.read()
                        
                    json_obj = json.loads(json_data)
                        
                    rsa   = base64.decodebytes(json_obj["RSA"].encode('ascii')) 
                    C     = base64.decodebytes(json_obj["C"].encode('ascii')) 
                    tag   = base64.decodebytes(json_obj["Tag"].encode('ascii')) 
                    IV    = base64.decodebytes(json_obj["IV"].encode('ascii')) 
                    ext   = base64.decodebytes(json_obj["Ext"].encode('ascii')) 

                    #print("\ndecrypt rsa =",rsa)
                    #print("\ndecrypt C =",C)
                    #print("\ndecrypt tag =",tag)
                    #print("\ndecrypt IV =",IV)
                    
                    plaintext = my_RSA_decrypt(file_name, rsa, C, IV, tag, ext, rsa_privatekey_filepath)
                    
                    #print("decrypt_all() plaintext", plaintext)
                    
                    out_filepath = root + "/" + str(file_count) + "DECRYPTED" + ext.decode('utf-8')
                    file_count += 1
                    
                    #print("decrypt_all() out_file_path", out_file_path)
            
                    file_out = open(out_filepath, "wb")
                    file_out.write(plaintext)
                    file_out.close()
            
                    os.remove(in_filepath)

#####################################################################################################################################################################
                    
directory = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc"
pubf = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/blueberry.pem"
privf = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/blackberry.pem"

pbk, prk = generate_keys(pubf, privf) 
print("\nReady to Encrypt? Press Enter")
input()    
 
print("********************************ENCRYPT********************************")
encrypt_all(directory, pbk)

print("\nReady to Decrypt? Press Enter")
input()
print("********************************DECRYPT********************************")
decrypt_all(directory, prk)
