# Malware Development Essentials Project - Sektor7
This is the summary of malware development essentials by sektor7.
## Usage
the program I wrote takes a different approach as it gives you a terminal-like experience and you have to type commands.

to use it you have to compile it first and just run it. after running press `h` or `help` to for it to show the help menu.
## Encryption Script
The script i wrote for encryption is the following:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
from os import urandom
import sys
from typing import List
import string
from random import choice

def aes_encrypt(data:bytes, key:bytes) -> bytes:
    key = hashlib.sha256(key).digest()
    iv = b'\x00' * 16
    padded_data = pad(data, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_data)

def XOR(data:bytes, key:str) -> bytes:
    data_array = bytearray(data) #modifable when bytearray    
    for i in range(len(data_array)):
        current_key = key[i % len(key)]
        data_array[i] ^=  ord(current_key)
    return bytes(data_array)

def print_help(plaintext,data:str|bytes, key:str|bytes,type:str) -> str:
    #string 
    value = "{" + ", ".join(hex(x) for x in data) + "}"
    #if it's a dll name get the text before .dll
    if plaintext.find(".") != -1: plaintext = plaintext.split('.')[0]
    #uppercase the first letter
    plaintext = plaintext[0].upper()+plaintext[1:]
    print(f"unsigned char s{plaintext}[] = {value};")
    
    if type=="xor":
        #key
        print(f"char k{plaintext}[] = \"{key}\";")
        #decryption function
        print(f"XOR(s{plaintext}, sizeof(s{plaintext}),  k{plaintext}, sizeof(k{plaintext}));\n")
    elif type=="aes":
        key_value = "{" + ", ".join(hex(x) for x in key) + "}"
        print(f"char k{plaintext}[] = {key_value};")
        #decrytion function
        print(f"AESDecrypt(s{plaintext}, sizeof(s{plaintext}),  k{plaintext}, sizeof(k{plaintext}));\n")
        
def XOR_key_generator(length:int) -> str:
    letters = 'abcdefghijklmnopqrstuvwxyz'
    key = ""
    for i in range(length):
        key += choice(letters)
    return key

if sys.argv[1] == "string":
    strings:List[str] = sys.argv[2].split(',')
    for string in strings:
        key = XOR_key_generator(10)
        xored = XOR((string.encode()+b'\x00'),key)
        print_help(string,xored,key,"xor")

elif sys.argv[1] == "file":
    f = open(sys.argv[2],"rb")
    key = urandom(16)
    encrypted = aes_encrypt(f.read(),key) 
    print_help("data",encrypted, key,"aes")
else:
    print("help:\n\tmain.py file <filename>\n\tmain.py string <string1,string2,string3>")


```