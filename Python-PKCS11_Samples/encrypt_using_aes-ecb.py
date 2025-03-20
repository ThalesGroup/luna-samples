#!/usr/bin/env python3
#*********************************************************************************
#                                                                                *
# This file is part of the "luna-samples" project.                               *
#                                                                                *
# The "luna-samples" project is provided under the MIT license (see the          *
# following Web site for further details: https://mit-license.org/ ).            *
#                                                                                *
# Copyright © 2025 Thales Group                                                  *
#                                                                                *
#*********************************************************************************

# OBJECTIVE:
# - This sample code demonstrates how to use a generated AES-128 key to encrypt a plaintext.
# - For encryption, this sample uses AES-ECB mechanism


import sys
import os
import getpass
import pkcs11
from pkcs11 import Mechanism
from pkcs11.exceptions import PinIncorrect, NoSuchToken

print("\nencrypt_using_aes-ecb.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=2:
	print ("Usage:")
	print ("./encrypt_using_aes-ecb.py <slot_label>")
	print ("\nExample:")
	print ("./encrypt_using_aes-ecb.py SP_SKS_SEHSM3\n")
	quit()

slot_label = sys.argv[1]


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


# Login as crypto officer.
co_pass = getpass.getpass(prompt="Crypto officer password: ")


# Accepts plaintext to encrypt and checks if it is of correct size.
plaintext = input("Enter plaintext to encrypt : ")
if (len(plaintext)%16!=0):
	print ("Text too small/big for AES-ECB\n")
	quit()


try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Find the slot to connect to.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session: #Opens a new session and logs in as crypto officer.
		print("Login success.")
		secret_key = p11session.generate_key(pkcs11.KeyType.AES, 128, store=False) # Generates AES key.
		print ("AES-128 key generated.")
		encrypted_text = secret_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB); # Encrypts plaintext.
		print ("Plaintext encrypted.")
		decrypted_text = secret_key.decrypt(encrypted_text, mechanism=Mechanism.AES_ECB); # Decrypts plaintext.
		print ("Encrypted text decrypted.\n")
		print ("Plain text	: ", plaintext)
		print ("Plain text (hex): ", plaintext.encode().hex())
		print ("Encrypted text	: ", encrypted_text.hex())
		print ("Decrypted text	: ", decrypted_text.hex())
		print ()

except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
