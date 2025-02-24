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
# - This sample code demonstrates how to generate an AES key.
# - It allows you to set your own key label and choose a key size.


import sys
import os
import getpass
import pkcs11
from pkcs11 import Attribute, KeyType
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken, AttributeValueInvalid

print("\ngenerate_aes_key.py\n")

if len(sys.argv)!=4:
	print ("Usage:")
	print ("./generate_aes_key.py <slot_label> <secret_key_label> <keysize (128/192/256)>")
	print ("\nExample:")
	print ("./generate_aes_key.py SP_SKS_SEHSM3 myAesKey 128\n")
	quit()

slot_label = sys.argv[1]
secret_key_label = sys.argv[2]
key_size = int(sys.argv[3])
if ( (key_size!=128) and (key_size!=192) and (key_size!=256) ):
	print("AES key size invalid.\n")
	quit()
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


co_pass = getpass.getpass(prompt="Crypto officer password: ")


try:
	p11 = pkcs11.lib(pkcs11_library)
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label)
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session:
		print("Login success.")
		secret_key = p11session.generate_key(pkcs11.KeyType.AES, key_size, template={
			Attribute.TOKEN: True,
			Attribute.ID: "1123581321345589".encode('UTF-8'),
			Attribute.PRIVATE: True,
			Attribute.EXTRACTABLE: True,
			Attribute.MODIFIABLE: True,
			Attribute.SENSITIVE: True,
			Attribute.WRAP: True,
			Attribute.UNWRAP: True,
			Attribute.ENCRYPT: True,
			Attribute.DECRYPT: True,
			Attribute.SIGN: True,
			Attribute.VERIFY: True,
			Attribute.LABEL: secret_key_label
		})
		print ("AES-256 key generated with label : ", secret_key_label)
except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except AttributeValueInvalid:
	print ("Attribute value invalid.\n")
except RuntimeError as rterr:
	print (rterr)
