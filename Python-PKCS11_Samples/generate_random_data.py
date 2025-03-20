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
# - This sample demonstrates how to generate random data.

import sys
import os
import getpass
import pkcs11
from pkcs11.exceptions import PinIncorrect, NoSuchToken

print ("./generate_random_bytes.py\n")


# Prints the syntax for executing this code.
if len(sys.argv)!=3:
	print ("Usage:")
	print ("./generate_random_data.py <slot_label> <data_size (bytes)>")
	print ()
	print ("Example:")
	print ("./generate_random_data.py SEHSM2 32\n")
	quit()

slot_label = sys.argv[1]
data_size = int(sys.argv[2])


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()

co_pass = getpass.getpass(prompt="Crypto Officer Password: ")

try:
	p11 = pkcs11.lib(pkcs11_library) # Loads pkcs11 library.
	print ("PKCS11 library found at : ", pkcs11_library)

	p11token = p11.get_token(token_label=slot_label) # Finds the specified slot.
	print("Token found : ", slot_label)

	with p11token.open(user_pin=co_pass) as p11session: #Opens a new session and logs in as crypto officer.
		print("Login success.")
		random_data = p11session.generate_random(data_size*8) # Generates random data using size specified as bits.
		print (data_size, "bytes of random data generated.")
		print ("Random Data (hex) :", random_data.hex())
		print ()
except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
