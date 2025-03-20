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
# - This sample code demonstrates how to generate RSA keypair and use it for encryption.
# - Encryption is performed using rsa-pkcs1 mechanism.


import sys
import os
import getpass
import pkcs11
from pkcs11 import KeyType, Mechanism
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken

print("\nencrypt_using_rsa_pkcs1.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=2:
	print ("Usage:")
	print ("./encrypt_using_rsa_pkcs1.py <slot_label>")
	print ("\nExample:")
	print ("./encrypt_using_rsa_pkcs1.py SP_SKS_SEHSM3\n")
	quit()

slot_label = sys.argv[1]


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()



co_pass = getpass.getpass(prompt="Crypto officer password: ")
plaintext = input("Enter plaintext to encrypt : ")
if (len(plaintext)>245):
	print("Plaintext too long.\n")
	quit()


try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Find the specified slot.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session: #Opens a new session and logs in as crypto officer.
		print("Login success.")
		rsa_pub, rsa_pri = p11session.generate_keypair(pkcs11.KeyType.RSA, 2048, store=False) # Generates rsa-2048 keypair as session objects.
		print ("RSA-2048 keypair generated.")
		encrypted_text = rsa_pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS); # Encrypts plaintext.
		print ("Plaintext encrypted.")
		decrypted_text = rsa_pri.decrypt(encrypted_text, mechanism=Mechanism.RSA_PKCS); # Decrypts plaintext.

		print ("Encrypted data decrypted.\n")
		print ("Plain text	: ", plaintext)
		print ("Plain text (hex): ", plaintext.encode().hex())
		print ("Encrypted text	: ", encrypted_text.hex())
		print ("Decrypted text  : ", decrypted_text.hex())
		print ()
except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
