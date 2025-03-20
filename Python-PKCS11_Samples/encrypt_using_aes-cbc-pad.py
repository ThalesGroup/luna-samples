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
# - For encryption, this sample uses AES-CBC-PAD mechanism


import sys
import os
import getpass
import pkcs11
from pkcs11 import Mechanism
from pkcs11.exceptions import PinIncorrect, NoSuchToken

print("\nencrypt_using_aes-cbc-pad.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=2:
	print ("Usage:")
	print ("./encrypt_using_aes-cbc-pad.py <slot_label>")
	print ("\nExample:")
	print ("./encrypt_using_aes-cbc-pad.py SP_SKS_SEHSM3\n")
	quit()

slot_label = sys.argv[1]


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


# Input for crypto officer password and the plaintext to encrypt.
co_pass = getpass.getpass(prompt="Crypto officer password: ")
plaintext = input("Enter plaintext to encrypt : ");


try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Find the slot to connect to.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session:
		print("Login success.")
		secret_key = p11session.generate_key(pkcs11.KeyType.AES, 128, store=False) # Generates AES-128 bit key as a session object.
		print ("AES-128 key generated.")
		iv = p11session.generate_random(128) # Generating 8 bytes of random IV.
		encrypted_text = secret_key.encrypt(plaintext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv); # Encrypts plaintext.
		print ("Plaintext encrypted.")
		decrypted_text = secret_key.decrypt(encrypted_text, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv); # Decrypts plaintext.
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
	print(sys.exc_info()[0])
	print()
