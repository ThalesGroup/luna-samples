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
# - This sample code demonstrates how to generate RSA keypair.
# - It allows you to set your own labels and choose a keypair size.


import sys
import os
import getpass
import pkcs11
from pkcs11 import Attribute, KeyType
from pkcs11.exceptions import NoSuchKey, PinIncorrect, NoSuchToken, AttributeValueInvalid

print("\ngenerate_rsa_keypair.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=4:
	print ("Usage:")
	print ("./generate_rsa_keypair.py <slot_label> <keypair_label> <keysize (BITS)>")
	print ("\nExample:")
	print ("./generate_rsa_keypair.py SP_SKS_SEHSM3 testRSA 2048\n")
	quit()


slot_label = sys.argv[1]
keypair_label = sys.argv[2]
keypair_size = int(sys.argv[3])
if ( (keypair_size<512) and (keypair_size>8192) ): # Checks the keysize.
	print("RSA keypair size invalid.\n")
	quit()


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
		rsa_pub, rsa_pri = p11session.generate_keypair(pkcs11.KeyType.RSA, keypair_size, label=keypair_label, store=True) # Generates RSA keypair as token objects.
		print ("RSA key generated with label : ", keypair_label)
		print ("\t > Private Key : ", rsa_pri)
		print ("\t > Public Key : ", rsa_pub)
		print ()
except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except AttributeValueInvalid:
	print ("Attribute value invalid.\n")
except:
	print (sys.exc_info()[0])
	print ()
