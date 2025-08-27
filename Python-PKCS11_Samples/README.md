## PYTHON-PKCS11 SAMPLES FOR LUNA HSMs

The Python codes in this directory utilises the python-pkcs11 package as a high-level PKCS#11 API.
These samples demonstrates how to execute various cryptographic operations using python-pkcs11 package. <br><br>

URL : https://python-pkcs11.readthedocs.io/en/latest/#



<BR><BR>
### WARNING AND DISCLAIMER
- These sample codes were written solely for learning and testing purposes.
- Please refer to the python-pkcs11 documentation to understand the details of this API.
- These sample codes SHOULD NOT be used as-is in a production environment.



<BR><BR>
### REQUIRED PYTHON PACKAGES.
These samples may require these packages to be installed.
- python-pkcs11. On Ubuntu, install using 'sudo apt install python3-pkcs11'.
- getpass


<BR><BR>
### List of samples.
| SAMPLE NAME | DESCRIPTION |
| --- | --- |
| enumerate_slots.py | demonstrates how to display token-ready slots. |
| login_logout.py | demonstrates how to login using crypto officer a.k.a CKU_USER. |
| generate_random_data.py | demonstrates how to generate random data using Luna HSM's RNG. |
| generate_aes_key.py | demonstrates how to generate an AES key. |
| generate_aes_key2.py | demonstrates how to generate an AES key using user specified pkcs11 attributes. |
| generate_rsa_keypair.py | demonstrates how to generate an RSA keypair. |
| generate_rsa_keypair2.py | demonstrates how to generate an RSA keypair using user specified pkcs11 attributes. |
| generate_ecdsa_keypair.py | demonstrates how to generate ECDSA keypair. |
| list_objects.py | demonstrates how to list objects in a partition. |
| sign_using_ecdsa_sha256.py | demonstrates signing using ecdsa-sha256. |
| sign_using_ecdsa_sha512.py | demonstrates signing using ecdsa-sha512. |
| sign_using_rsa.py | demonstrates signing using rsa-sha512. |
| sign_using_rsa_pkcs1.py | demonstrates signing using rsa-pkcs1.|
| sign_using_rsa_pss.py | demonstrates signing using rsa-pss. |
| sign_using_rsa_pss_sha256.py | demonstrates signing using rsa-pss-sha256. |
| sign_using_rsa_sha256.py | demonstrates signing using rsa-sha256. |
| encrypt_using_aes-cbc-pad.py | demonstrates encryption using aes-cbc-pad. |
| encrypt_using_aes-cbc.py | demonstrates encryption using aes-cbc. |
| encrypt_using_aes-ecb.py | demonstrates encryption using aes-ecb. |
| encrypt_using_rsa_oaep.py | demonstrates encryption using rsa-oaep. |
| encrypt_using_rsa_pkcs1.py | demonstrates encryption using rsa-pkcs1. |
| wrap_secret_key_using_aes.py | demonstrates how to wrap a secret key using an AES key. |
| wrap_secret_key_using_rsa_pkcs1.py | demonstrates how to wrap a secret key using RSA-PKCS1. |
| wrap_secret_key_using_rsa_oaep_sha1.py | demonstrates how to wrap a secret key using RSA-OAEP-MGF-SHA1. |
| wrap_secret_key_using_rsa_oaep_sha256.py | demonstrates how to wrap a secret key using RSA-OAEP-MGF-SHA256. |
| unwrap_secret_key_using_aes.py | demonstrates how to unwrap a wrapped secret key using an AES-key. |
| unwrap_secret_key_using_rsa_pkcs1.py | demonstrates how to unwrap a secret using RSA-PKCS1. |
| unwrap_secret_key_using_rsa_oaep_sha1.py | demonstrates how to unwrap using RSA-OAEP-MGF-SHA1. |
| unwrap_secret_key_using_rsa_oaep_sha256.py | demonstrates how to unwrap using RSA-OAEP-MGF-SHA256. |


<BR><BR>
### How to execute these samples?
- Set P11_LIB environment variable to point to the cryptoki library. Without P11_LIB set, the sample codes will fail to execute properly.
```
sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ ./enumerate_slots.py

enumerate_slots.py
*** P11_LIB environment variable not set. ***
> export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so

sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
```

- Some of these samples can be executed without passing any argument.
```
sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ ./enumerate_slots.py

Slot Description: Net Token Slot
Manufacturer ID: Safenet, Inc.
Hardware Version: 0.0
Firmware Version: 0.0
Flags: 7
-----------------

Slot Description: Net Token Slot
Manufacturer ID: Safenet, Inc.
Hardware Version: 0.0
Firmware Version: 0.0
Flags: 7
-----------------

Slot Description: HA Virtual Card Slot
Manufacturer ID: Safenet, Inc.
Hardware Version: 0.0
Firmware Version: 7.8
Flags: 5
-----------------
```

- Sample codes that require command-line arguments will display the correct syntax when executed without any argument.
```
sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ ./login_logout.py

login_logout.py

usage :-
./login_logout.py <slot_label>



sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ vtl ver
vtl (64-bit) v10.7.2-16. Copyright (c) 2024 Thales Group. All rights reserved.

The following Luna SA Slots/Partitions were found:

Slot    Serial #                Label
====    ================        =====
   0       1682975235230        SP_SKS_SEHSM3

sampaul@thales:~/LunaHSM_Sample_Codes/Python-PKCS11$ ./login_logout.py SP_SKS_SEHSM3

login_logout.py

Crypto Officer Password:
PKCS11 library found at :  /usr/safenet/lunaclient/lib/libCryptoki2_64.so
Token found :  SP_SKS_SEHSM3
Login success.
Logout success.

```
- When you type a password, the characters are not displayed on the screen.
