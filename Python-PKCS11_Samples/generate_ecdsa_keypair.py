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
# - This sample code demonstrates how to generate ECDSA keypair.
# - The keypair is generated using a user specified ECC Curve.


import sys
import os
import getpass
import pkcs11
from pkcs11 import Attribute, KeyType
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken, AttributeValueInvalid

print("\ngenerate_ecdsa_keypair.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=4:
	print ("Usage:")
	print ("./generate_ecdsa_keypair.py <slot_label> <keypair_label> <curve>")
	print ("\nExample:")
	print ("./generate_ecdsa_keypair.py SP_SKS_SEHSM3 testECDSA secp256r1\n")
	quit()

slot_label = sys.argv[1]
keypair_label = sys.argv[2]
curve_id = sys.argv[3]


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


co_pass = getpass.getpass(prompt="Crypto officer password: ")


try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Finds the specified slot.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session: #Opens a new session and logs in as crypto officer.
		print("Login success.")
		# Generates ECParam
		eccParam = p11session.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(curve_id)}, local=True);

		# Generates ECDSA keypair using the param.
		ecc_pub, ecc_pri = eccParam.generate_keypair(label=keypair_label, store=True);
		print ("ECDSA key generated with label : ", keypair_label)
		print ("\t > Private Key : ", ecc_pri)
		print ("\t > Public Key : ", ecc_pub)
		print ()
except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
