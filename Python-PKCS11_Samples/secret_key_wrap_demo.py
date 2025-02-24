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
# - This sample code demonstrate how to wrap a secret key using another wrapping key (also a secret key).
# - The encrypted key bytes will be written to a file.



import sys
import os
import getpass
import pkcs11
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken

print ("\nsecret_key_wrap_demo.py\n")

if len(sys.argv)!=5:
	print ("Usage:")
	print ("./secret_key_wrap_demo.py <slot_label> <wrapping_key_label> <key_to_wrap_label> <output_file_name>\n")
	print ("Example:")
	print ("./secret_key_wrap_demo.py SP_SKS_SEHSM3 MasterKey DataKey DataKey.dat\n")
	quit()

try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()

slot_label = sys.argv[1]
wrapping_key_label = sys.argv[2]
key_to_wrap_label = sys.argv[3]
outfile = sys.argv[4]
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
			print (wrapping_key_label, " not found.\n")

		try:
			key_to_wrap = p11session.get_key(label=key_to_wrap_label)
			print ("\t> Key to wrap found : ", key_to_wrap_label)
		except:
			print (key_to_wrap_label, " not found.\n")

		wrapped_key_data = wrapping_key.wrap_key(key_to_wrap)
		try:
			with open(outfile, "wb") as file:
				file.write(wrapped_key_data)
				file.close()
				print ("Wrapped key written to file ", outfile, "\n")
		except Exception as err:
			print ("Writing wrapped key to ", outfile, " failed. REASON: ", err, "\n")


except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except RuntimeError as rterr:
	print (rterr)
