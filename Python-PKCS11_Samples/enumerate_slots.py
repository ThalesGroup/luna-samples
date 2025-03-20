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


# OBJECTIVE: This code demonstrates how to enumerate "Token Ready" slots.


import pkcs11
import os

print ("\nenumerate_slots.py\n")


# Reads P11_LIB environment variable.
try:
	p11_lib = pkcs11.lib(os.environ['P11_LIB'])
except:
	print("*** P11_LIB environment variable not set. ***")
	print("> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so\n")
	quit()


slots = p11_lib.get_slots(token_present=True) # Finds the specified slot.

# Exits if not slots were found or prints the detected slots.
if (len(slots)==0):
	print("No slots were found.\n")
	quit()
else:
	print()
	for slot in slots:
		print(slot)
		print("-----------------\n")

