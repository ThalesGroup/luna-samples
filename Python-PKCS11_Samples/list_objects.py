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
# - This sample code demonstrates how to list objects from a slot.
# - It gives you the option to choose what to list.
# - Options are certificates, public keys, private key, secret key and all objects.


import sys
import os
import getpass
import pkcs11
from pkcs11.constants import ObjectClass, Attribute
from pkcs11.exceptions import PinIncorrect, NoSuchToken

print("\nlist_objects.py\n")

if len(sys.argv)!=3:
	print ("Usage:")
	print ("./list_objects.py <slot_label> -<OBJECT_TYPE>\n")
	print ("-<OBJECT_TYPE> : \n")
	print ("  -secret  : lists all secret keys\n")
	print ("  -private : lists private keys\n")
	print ("  -public  : lists public keys\n")
	print ("  -cert    : lists all certificates\n")
	print ("  -all	   : lists all objects\n")
	print ("\nExample:")
	print ("./list_objects.py SP_SKS_SEHSM3 -secret\n")
	quit()

slot_label = sys.argv[1]
object_type = sys.argv[2]

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
		if(object_type=="-cert"):
			print ("Certificates:")
			for p11_object in p11session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}): print("  - ", p11_object.label)
		elif(object_type=="-public"):
			print ("Public Keys:")
			for p11_object in p11session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}): print("  - ", p11_object.label)
		elif(object_type=="-private"):
			print ("Private Keys:")
			for p11_object in p11session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}): print("  - ", p11_object.label)
		elif(object_type=="-secret"):
			print ("Secret Keys:")
			for p11_object in p11session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}): print("  - ", p11_object.label)
		elif(object_type=="-all"):
			print ("All objects:")
			for p11_object in p11session.get_objects({Attribute.TOKEN: 1}): print("  -", p11_object.label)
		else:
			print ("Invalid search option used.")


except PinIncorrect:
	print ("Incorrect crypto officer pin.\n")
except NoSuchToken:
	print ("Incorrect token label.\n")
except RuntimeError as rterr:
	print (rterr)
