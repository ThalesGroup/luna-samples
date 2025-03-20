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
# - This sample demonstrates how to wrap a secret key using an RSA public key.
# - It uses CKM_RSA_PKCS_OAEP mechanism, with MGF-SHA256 as the oaep parameter to perform wrapping operation.
# - The target is an AES-256 key.

import sys
import os
import getpass
import pkcs11
from pkcs11.mechanisms import Mechanism, MGF
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken


print ("\nwrap_secret_key_using_rsa_oaep_sha256.py\n")


# Checks for all required arguments.
if len(sys.argv)!=5:
	print ("Usage:")
	print ("./wrap_secret_key_using_rsa_oaep_sha256.py <slot_label> <rsa_public_key_label> <aes_key_label> <output_filename>\n")
	print ("Example:")
	print ("./wrap_secret_key_using_rsa_oaep_sha256.py SP_SKS_SEHSM3 aws-public-key BYOK-AWS-AES BYOK.dat\n")
	quit()


# Checks if the P11_LIB environment variable is set.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


# Stores all arguments in a variable.
slot_label = sys.argv[1]
public_key_label = sys.argv[2]
aes_key_label = sys.argv[3]
outfile = sys.argv[4]
co_pass = getpass.getpass(prompt="Crypto officer password: ")


# Loads pkcs11 library, logs into the specified slot, and performs C_Wrap
try:
	p11 = pkcs11.lib(pkcs11_library)
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label)
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session:
		print ("\t> Login success.")

		try:
			# Search for the public key.
			wrapping_key = p11session.get_key(label=public_key_label)
			print ("\t> Public key found : ", public_key_label)
		except:
			print (public_key_label, " not found.\n")

		try:
			# Search for the AES key.
			key_to_wrap = p11session.get_key(label=aes_key_label)
			print ("\t> Key to wrap found : ", aes_key_label)
		except:
			print (aes_key_label, " not found.\n")

		# wrap aes key using RSA public key.
		param = (Mechanism.SHA256, MGF.SHA256, None)
		wrapped_key_data = wrapping_key.wrap_key(key_to_wrap, mechanism_param=param)


		# Write wrapped data to file.
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
except:
	print (sys.exc_info()[0])
	print ()
