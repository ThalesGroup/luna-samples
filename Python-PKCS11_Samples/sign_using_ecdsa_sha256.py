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
# - This sample code demonstrates use an ecdsa keypair to digitally sign a text.
# - Text will be signed using ecdsa-sha256 mechanism.


import sys
import os
import getpass
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken, AttributeValueInvalid

print("\nsign_using_ecdsa_sha256.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=2:
	print ("Usage:")
	print ("./sign_using_ecdsa_sha256.py <slot_label>")
	print ("\nExample:")
	print ("./sign_using_ecdsa_sha256.py SP_SKS_SEHSM3\n")
	quit()

slot_label = sys.argv[1]
curve_id = "secp384r1"

# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


co_pass = getpass.getpass(prompt="Crypto officer password: ")
plaintext = input("Enter plaintext to sign : ")

try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Finds the specified slot.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session: #Opens a new session and logs in as crypto officer.
		print("Login success.")

		# Generates ECParam
		eccParam = p11session.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(curve_id)}, local=True)

		# Generates ECDSA keypair using the param.
		ecc_pub, ecc_pri = eccParam.generate_keypair(store=False)
		print ("ECDSA key pair generated.")

		signature = ecc_pri.sign(plaintext, mechanism=Mechanism.ECDSA_SHA256)
		print ("Plaintext signed.")

		if(ecc_pub.verify(plaintext, signature, mechanism=Mechanism.ECDSA_SHA256)):
			print ("Signature verified.")
		else:
			print ("Signature verification failed.")

		print ()
		print ("Plain text 	: ", plaintext)
		print ("Plain text (Hex): ", plaintext.encode().hex())
		print ("Signature	: ", signature.hex())

except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
