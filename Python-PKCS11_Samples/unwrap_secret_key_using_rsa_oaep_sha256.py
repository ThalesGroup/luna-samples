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
# - This sample code demonstrates how to unwrap an encrypted secret key (wrapped key) from a file onto HSM.
# - An rsa-2048 private key is used for unwrapping the encrypted secret.
# - For unwrapping, this sample uses CKM_RSA_PKCS_OAEP with MGF1.SHA256 as the oaep parameter.


import sys
import os
import getpass
import pkcs11
from pkcs11 import ObjectClass, KeyType
from pkcs11.mechanisms import Mechanism, MGF
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken

print ("\nunwrap_secret_key_using_rsa_oaep_sha256\n")


# Checks for all required arguments.
if len(sys.argv)!=5:
	print ("Usage:")
	print ("./unwrap_secret_key_using_rsa_oaep_sha256 <slot_label> <wrapping_key_label> <unwrapped_key_label> <wrapped_key_file>\n")
	print ("Example:")
	print ("./unwrap_secret_key_using_rsa_oaep_sha256 SP_SKS_SEHSM3 RSA-Private-Key myAesKey myAesKey.dat\n")
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
private_key_label = sys.argv[2]
unwrapped_key_label = sys.argv[3]
wrapped_key_file = sys.argv[4]
co_pass = getpass.getpass(prompt="Crypto officer password: ")



# Loads pkcs11 library, logs into the specified slot, and performs C_Unwrap
try:
	p11 = pkcs11.lib(pkcs11_library)
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label)
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session:
		print ("\t> Login success.")

		try:
			wrapping_key = p11session.get_key(label=private_key_label)
			print ("\t> Wrapping key found : ", private_key_label)
		except:
			print (private_key_label, " not found.\n")

		try:
			with open(wrapped_key_file, "rb") as file:
				wrapped_key = file.read()
				file.close()
		except Exception as err:
			print ("Reading ", wrapped_key_file, " failed. REASON: ", err)


		try:
			params = (Mechanism.SHA256, MGF.SHA256, None) # OAEP parameters required for unwrapping
			unwrapped_key = wrapping_key.unwrap_key(ObjectClass.SECRET_KEY, KeyType.AES, wrapped_key, label=unwrapped_key_label, store=True, mechanism_param=params)
			print ("Key unwrapped successfully.\n")
		except Exception as err:
			print ("Unwrapping failed. Reason: ", err)

except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
