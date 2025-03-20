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

# OBJECTIVE: This code uses the high-level pkcs11 api to demonstrates how to login as a crypto-officer (CKU_USER) and logout.



import os
import sys
import getpass
import pkcs11

print ("\nlogin_logout.py\n")


# Prints the syntax for executing this code.
if len(sys.argv) != 2:
	print ("usage :-")
	print ("./login_logout.py <slot_label>")
	print ("\nExample:")
	print ("./login_logout.py SP_SKS_SEHSM3\n")
	quit()

slot_label = sys.argv[1]


# Reads P11_LIB environment variable.
try:
	pkcs11_library = os.environ['P11_LIB']
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()

co_pass = getpass.getpass(prompt="Crypto Officer Password: ")
try:
	# Loads pkcs11 library
	p11 = pkcs11.lib(pkcs11_library)
	print ("PKCS11 library found at : ", pkcs11_library)

	# gets a token with a specified label
	p11token = p11.get_token(token_label=slot_label)
	print("Token found : ", slot_label)

	# opens new session and login
	p11session = p11token.open(user_pin=co_pass)
	print("Login success.")

	# closes the session.
	p11session.close()
	print("Logout success.\n")

except pkcs11.exceptions.PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except pkcs11.exceptions.NoSuchToken:
	print ("Incorrect token label.\n")
except:
	print (sys.exc_info()[0])
	print ()
