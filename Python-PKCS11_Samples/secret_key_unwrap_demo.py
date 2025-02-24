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
# - This sample code demonstrates how to unwrap an encrypted secret key from a file onto HSM.
# - The secret key used for wrapping (i.e. the wrapping key), is required to unwrap the encrypted secret.



import sys
import os
import getpass
import pkcs11
from pkcs11 import ObjectClass, KeyType, Attribute
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken

print ("\nsecret_key_unwrap_demo.py\n")

if len(sys.argv)!=5:
	print ("Usage:")
	print ("./secret_key_unwrap_demo.py <slot_label> <wrapping_key_label> <unwrapped_key_label> <wrapped_key_file>\n")
	print ("Example:")
	print ("./secret_key_unwrap_demo.py SP_SKS_SEHSM3 KEK myEncryptionKey2 myEncryptionKey.dat\n")
	quit()

try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()

slot_label = sys.argv[1]
wrapping_key_label = sys.argv[2]
unwrapped_key_label = sys.argv[3]
wrapped_key_file = sys.argv[4]
co_pass = getpass.getpass(prompt="Crypto officer password: ")


try:
	p11 = pkcs11.lib(pkcs11_library)
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label)
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session:
		print ("\t> Login success.")

		try:
			wrapping_key = p11session.get_key(label=wrapping_key_label)
			print ("\t> Wrapping key found : ", wrapping_key_label)
		except:
			print (wrapping_key_label, " not found.")

		try:
			with open(wrapped_key_file, "rb") as file:
				wrapped_key = file.read()
				file.close()
		except Exception as err:
			print ("Reading ", wrapped_key_file, " failed. REASON: ", err)


		try:
			unwrapped_key = wrapping_key.unwrap_key(ObjectClass.SECRET_KEY, KeyType.AES, wrapped_key, label=unwrapped_key_label,store=True, template={
				Attribute.PRIVATE: True,
				Attribute.SENSITIVE: True,
				Attribute.ENCRYPT: True,
				Attribute.DECRYPT: True,
				Attribute.EXTRACTABLE: True,
				Attribute.VALUE_LEN: len(wrapped_key)-8
			})
			print ("Key unwrapped successfully.\n")
		except Exception as err:
			print ("Unwrapping failed. Reason: ", err)


except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except RuntimeError as rterr:
	print (rterr)
