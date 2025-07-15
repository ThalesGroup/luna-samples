CC=gcc
INCLUDES=/usr/safenet/lunaclient/samples/include -I/usr/safenet/lunaclient/sdk/include -I/usr/safenet/lunaclient/sdk/external
LINKFLAGS=-ldl
OUTDIR=bin/
$(shell mkdir -p bin)


# This is the default make option.
default: all



# Connect_and_Disconnect sample.
Connect_and_Disconnect: Connect_and_Disconnect.c
	$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o ${OUTDIR}/Connect_and_Disconnect Connect_and_Disconnect.c



# Samples to demonstrate various encryption mechanisms.
CKM_DES3_CBC_PAD_demo: encryption/CKM_DES3_CBC_PAD_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_DES3_CBC_PAD_demo encryption/CKM_DES3_CBC_PAD_demo.c

CKM_AES_CBC_PAD_demo: encryption/CKM_AES_CBC_PAD_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_AES_CBC_PAD_demo encryption/CKM_AES_CBC_PAD_demo.c

CKM_AES_CTR_demo: encryption/CKM_AES_CTR_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_AES_CTR_demo encryption/CKM_AES_CTR_demo.c

CKM_AES_ECB_demo: encryption/CKM_AES_ECB_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_AES_ECB_demo encryption/CKM_AES_ECB_demo.c

CKM_AES_GCM_FIPS_demo: encryption/CKM_AES_GCM_FIPS_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_AES_GCM_FIPS_demo encryption/CKM_AES_GCM_FIPS_demo.c

CKM_AES_GCM_NON_FIPS_demo: encryption/CKM_AES_GCM_NON_FIPS_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_AES_GCM_NON_FIPS_demo encryption/CKM_AES_GCM_NON_FIPS_demo.c

CKM_RSA_PKCS_OAEP_demo: encryption/CKM_RSA_PKCS_OAEP_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_RSA_PKCS_OAEP_demo encryption/CKM_RSA_PKCS_OAEP_demo.c

CKM_RSA_PKCS_demo: encryption/CKM_RSA_PKCS_demo.c
	@mkdir -p bin/encryption
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/encryption/CKM_RSA_PKCS_demo encryption/CKM_RSA_PKCS_demo.c



# Samples for generating keys.
CKM_AES_KEY_GEN_demo: generating_keys/CKM_AES_KEY_GEN_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_AES_KEY_GEN_demo generating_keys/CKM_AES_KEY_GEN_demo.c

CKM_DES3_KEY_GEN_demo: generating_keys/CKM_DES3_KEY_GEN_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_DES3_KEY_GEN_demo generating_keys/CKM_DES3_KEY_GEN_demo.c

CKM_ECDH1_DERIVE_demo: generating_keys/CKM_ECDH1_DERIVE_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_ECDH1_DERIVE_demo generating_keys/CKM_ECDH1_DERIVE_demo.c

CKM_EC_KEY_PAIR_GEN_demo: generating_keys/CKM_EC_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_EC_KEY_PAIR_GEN_demo generating_keys/CKM_EC_KEY_PAIR_GEN_demo.c

CKM_NIST_PRF_KDF_demo: generating_keys/CKM_NIST_PRF_KDF_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_NIST_PRF_KDF_demo generating_keys/CKM_NIST_PRF_KDF_demo.c

CKM_PKCS5_PBKD2_demo: generating_keys/CKM_PKCS5_PBKD2_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_PKCS5_PBKD2_demo generating_keys/CKM_PKCS5_PBKD2_demo.c

CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo: generating_keys/CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo generating_keys/CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo.c

CKM_RSA_PKCS_KEY_PAIR_GEN_demo: generating_keys/CKM_RSA_PKCS_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_RSA_PKCS_KEY_PAIR_GEN_demo generating_keys/CKM_RSA_PKCS_KEY_PAIR_GEN_demo.c

CKM_SHA256_KEY_DERIVATION_demo: generating_keys/CKM_SHA256_KEY_DERIVATION_demo.c
	@mkdir -p bin/keygen
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_SHA256_KEY_DERIVATION_demo generating_keys/CKM_SHA256_KEY_DERIVATION_demo.c

CKM_EC_EDWARDS_KEY_PAIR_GEN_demo: generating_keys/CKM_EC_EDWARDS_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/keygen
	 @$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/keygen/CKM_EC_EDWARDS_KEY_PAIR_GEN_demo generating_keys/CKM_EC_EDWARDS_KEY_PAIR_GEN_demo.c



# Samples to demonstrate various signing mechanisms.
CKM_AES_CMAC_demo: signing/CKM_AES_CMAC_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_AES_CMAC_demo signing/CKM_AES_CMAC_demo.c

CKM_ECDSA_SHA256_demo: signing/CKM_ECDSA_SHA256_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_ECDSA_SHA256_demo signing/CKM_ECDSA_SHA256_demo.c

CKM_ECDSA_demo: signing/CKM_ECDSA_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_ECDSA_demo signing/CKM_ECDSA_demo.c

CKM_RSA_PKCS_2demo: signing/CKM_RSA_PKCS_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_RSA_PKCS_demo signing/CKM_RSA_PKCS_demo.c

CKM_SHA256_HMAC_demo: signing/CKM_SHA256_HMAC_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_SHA256_HMAC_demo signing/CKM_SHA256_HMAC_demo.c

CKM_SHA256_RSA_PKCS_PSS_demo: signing/CKM_SHA256_RSA_PKCS_PSS_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_SHA256_RSA_PKCS_PSS_demo signing/CKM_SHA256_RSA_PKCS_PSS_demo.c

CKM_SHA256_RSA_PKCS_demo: signing/CKM_SHA256_RSA_PKCS_demo.c
	@mkdir -p bin/signing
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/signing/CKM_SHA256_RSA_PKCS_demo signing/CKM_SHA256_RSA_PKCS_demo.c



# Samples to demonstrate object management.
CKM_AES_KWP_demo: object_management/CKM_AES_KWP_demo.c
	@mkdir -p bin/obj_management/
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/CKM_AES_KWP_demo object_management/CKM_AES_KWP_demo.c

CKM_AES_KW_demo: object_management/CKM_AES_KW_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/CKM_AES_KW_demo object_management/CKM_AES_KW_demo.c

C_CopyObjects_demo: object_management/C_CopyObjects_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_CopyObjects_demo object_management/C_CopyObjects_demo.c

C_CreateObject_demo: object_management/C_CreateObject_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_CreateObject_demo object_management/C_CreateObject_demo.c

C_DestroyObject_demo: object_management/C_DestroyObject_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_DestroyObject_demo object_management/C_DestroyObject_demo.c

C_FindObjects_demo: object_management/C_FindObjects_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_FindObjects_demo object_management/C_FindObjects_demo.c

C_GetAttributeValue_demo: object_management/C_GetAttributeValue_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_GetAttributeValue_demo object_management/C_GetAttributeValue_demo.c

C_SetAttributeValue_demo: object_management/C_SetAttributeValue_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/C_SetAttributeValue_demo object_management/C_SetAttributeValue_demo.c

CreateKnownKeys: object_management/CreateKnownKeys.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/CreateKnownKeys object_management/CreateKnownKeys.c

UnwrapTemplates_demo: object_management/UnwrapTemplates_demo.c
	@mkdir -p bin/obj_management
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/obj_management/UnwrapTemplates_demo object_management/UnwrapTemplates_demo.c



# Samples to demonstrate miscellaneous pkcs11 tasks.
C_GenerateRandom_demo: misc/C_GenerateRandom_demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/C_GenerateRandom_demo misc/C_GenerateRandom_demo.c

C_GetMechanismList_Demo: misc/C_GetMechanismList_Demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/C_GetMechanismList_Demo misc/C_GetMechanismList_Demo.c

C_SeedRandom_demo: misc/C_SeedRandom_demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/C_SeedRandom_demo misc/C_SeedRandom_demo.c

Crypto_User_Login: misc/Crypto_User_Login.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/Crypto_User_Login misc/Crypto_User_Login.c

C_GetMechanismInfo_demo: misc/C_GetMechanismInfo_demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/C_GetMechanismInfo_demo misc/C_GetMechanismInfo_demo.c

Usage_Limit_demo: misc/Usage_Limit_demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/Usage_Limit_demo misc/Usage_Limit_demo.c

MultiThread_Signing_demo: misc/MultiThread_Signing_demo.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/MultiThread_Signing_demo misc/MultiThread_Signing_demo.c
List_Available_Slots: misc/List_Available_Slots.c
	@mkdir -p bin/misc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/misc/List_Available_Slots misc/List_Available_Slots.c



# Samples to demonstrate SafeNet Extensions.
Show_Partition_Policies: sfnt_extension/Show_Partition_Policies.c
	@mkdir -p bin/sfntExtension
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/sfntExtension/Show_Partition_Policies sfnt_extension/Show_Partition_Policies.c

CA_SIMExtract_demo: sfnt_extension/CA_SIMExtract_demo.c
	@mkdir -p bin/sfntExtension
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/sfntExtension/CA_SIMExtract_demo sfnt_extension/CA_SIMExtract_demo.c

CA_SIMInsert_demo: sfnt_extension/CA_SIMInsert_demo.c
	@mkdir -p bin/sfntExtension
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/sfntExtension/CA_SIMInsert_demo sfnt_extension/CA_SIMInsert_demo.c

Per_Key_Authorization_demo: sfnt_extension/Per_Key_Authorization_demo.c
	@mkdir -p bin/sfntExtension
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/sfntExtension/Per_Key_Authorization_demo sfnt_extension/Per_Key_Authorization_demo.c




# Samples to demonstrate how to use PQC algorithms.
CKM_HSS_KEY_PAIR_GEN_demo: pqc/CKM_HSS_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX ${LINKFLAGS} -I$(INCLUDES) -o bin/pqc/CKM_HSS_KEY_PAIR_GEN_demo pqc/CKM_HSS_KEY_PAIR_GEN_demo.c

CKM_HSS_sign_demo: pqc/CKM_HSS_sign_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_HSS_sign_demo pqc/CKM_HSS_sign_demo.c

CKM_HSS_verify_demo: pqc/CKM_HSS_verify_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_HSS_verify_demo pqc/CKM_HSS_verify_demo.c

CKM_ML_DSA_KEY_PAIR_GEN_demo: pqc/CKM_ML_DSA_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_ML_DSA_KEY_PAIR_GEN_demo pqc/CKM_ML_DSA_KEY_PAIR_GEN_demo.c

CKM_ML_KEM_KEY_PAIR_GEN_demo: pqc/CKM_ML_KEM_KEY_PAIR_GEN_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_ML_KEM_KEY_PAIR_GEN_demo pqc/CKM_ML_KEM_KEY_PAIR_GEN_demo.c

CKM_ML_DSA_Sign_Verify_demo: pqc/CKM_ML_DSA_Sign_Verify_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_ML_DSA_Sign_Verify_demo pqc/CKM_ML_DSA_Sign_Verify_demo.c

CKM_HASH_ML_DSA_Sign_Verify_demo: pqc/CKM_HASH_ML_DSA_Sign_Verify_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_HASH_ML_DSA_Sign_Verify_demo pqc/CKM_HASH_ML_DSA_Sign_Verify_demo.c

CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo: pqc/CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo pqc/CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo.c

CKM_ML_KEM_Encapsulate_Decapsulate_demo: pqc/CKM_ML_KEM_Encapsulate_Decapsulate_demo.c
	@mkdir -p bin/pqc
	@$(CC) -DOS_UNIX $(LINKFLAGS) -I$(INCLUDES) -o bin/pqc/CKM_ML_KEM_Encapsulate_Decapsulate_demo pqc/CKM_ML_KEM_Encapsulate_Decapsulate_demo.c


# Compile all sample codes.
all: encryption signing keygen objmgmt misc sfntExtension pqc


# Compile and build all encryption samples.
encryption: CKM_DES3_CBC_PAD_demo CKM_AES_CBC_PAD_demo CKM_AES_CTR_demo \
CKM_AES_ECB_demo CKM_AES_GCM_FIPS_demo CKM_AES_GCM_NON_FIPS_demo \
CKM_RSA_PKCS_OAEP_demo CKM_RSA_PKCS_demo
	@echo " - Encryption samples have build successfully. Executables are inside bin/encryption directory."


# Compile and build all signing samples.
signing: CKM_AES_CMAC_demo CKM_ECDSA_SHA256_demo CKM_ECDSA_demo \
CKM_RSA_PKCS_2demo CKM_SHA256_HMAC_demo CKM_SHA256_RSA_PKCS_PSS_demo \
CKM_SHA256_RSA_PKCS_demo
	@echo " - Signing samples have build successfully. Executables are inside bin/signing directory."


# Compile and build all key generation samples.
keygen: CKM_AES_KEY_GEN_demo CKM_DES3_KEY_GEN_demo CKM_ECDH1_DERIVE_demo \
CKM_EC_KEY_PAIR_GEN_demo CKM_NIST_PRF_KDF_demo CKM_PKCS5_PBKD2_demo \
CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo CKM_RSA_PKCS_KEY_PAIR_GEN_demo CKM_SHA256_KEY_DERIVATION_demo \
CKM_EC_EDWARDS_KEY_PAIR_GEN_demo
	@echo " - Key generation samples have build successfully. Executables are inside bin/keygen directory."


# Compile and build all object management samples.
objmgmt: CKM_AES_KWP_demo CKM_AES_KW_demo C_CopyObjects_demo \
C_CreateObject_demo C_DestroyObject_demo C_FindObjects_demo \
C_GetAttributeValue_demo C_SetAttributeValue_demo CreateKnownKeys \
UnwrapTemplates_demo
	@echo " - Object Management samples have build successfully. Executables are inside bin/obj_management directory."


# Compile and build all miscellaneous samples.
misc: C_GenerateRandom_demo C_GetMechanismList_Demo C_SeedRandom_demo \
Crypto_User_Login C_GetMechanismInfo_demo Usage_Limit_demo \
MultiThread_Signing_demo List_Available_Slots
	@echo " - Miscellaneous samples have build successfully. Executables are inside bin/misc directory."


# Compile and build all SafeNet extension samples.
sfntExtension: Show_Partition_Policies CA_SIMInsert_demo CA_SIMExtract_demo \
Per_Key_Authorization_demo
	@echo " - SafeNet Extension samples have build successfully. Executables are inside bin/sfntExtension directory."


# Compile and build all PQC samples.
pqc: CKM_HSS_KEY_PAIR_GEN_demo CKM_HSS_sign_demo CKM_HSS_verify_demo CKM_ML_DSA_KEY_PAIR_GEN_demo CKM_ML_KEM_KEY_PAIR_GEN_demo \
CKM_ML_DSA_Sign_Verify_demo CKM_HASH_ML_DSA_Sign_Verify_demo CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo CKM_ML_KEM_Encapsulate_Decapsulate_demo
	@echo " - PQC samples have build successfully. Executables are inside bin/pqc directory."


clean:
	@rm -rf bin
	@echo "All executables removed."
	@echo


list_samples:
	@echo
	@echo "List of available samples"
	@echo
	@echo "- Connect_and_Disconnect"
	@echo
	@echo "[ ENCRYPTION SAMPLES ]"
	@echo "- CKM_DES3_CBC_PAD_demo"
	@echo "- CKM_AES_CBC_PAD_demo"
	@echo "- CKM_AES_CTR_demo"
	@echo "- CKM_AES_ECB_demo"
	@echo "- CKM_AES_GCM_FIPS_demo"
	@echo "- CKM_AES_GCM_NON_FIPS_demo"
	@echo "- CKM_RSA_PKCS_OAEP_demo"
	@echo "- CKM_RSA_PKCS_demo"
	@echo
	@echo "[ KEY GENERATION SAMPLES ]"
	@echo "- CKM_AES_KEY_GEN_demo"
	@echo "- CKM_DES3_KEY_GEN_demo"
	@echo "- CKM_ECDH1_DERIVE_demo"
	@echo "- CKM_EC_KEY_PAIR_GEN_demo"
	@echo "- CKM_NIST_PRF_KDF_demo"
	@echo "- CKM_PKCS5_PBKD2_demo"
	@echo "- CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo"
	@echo "- CKM_RSA_PKCS_KEY_PAIR_GEN_demo"
	@echo "- CKM_SHA256_KEY_DERIVATION_demo"
	@echo "- CKM_EC_EDWARDS_KEY_PAIR_GEN_demo"
	@echo
	@echo "[ SIGNING SAMPLES ]"
	@echo "- CKM_AES_CMAC_demo"
	@echo "- CKM_ECDSA_SHA256_demo"
	@echo "- CKM_ECDSA_demo"
	@echo "- CKM_RSA_PKCS_2demo"
	@echo "- CKM_SHA256_HMAC_demo"
	@echo "- CKM_SHA256_RSA_PKCS_PSS_demo"
	@echo "- CKM_SHA256_RSA_PKCS_demo"
	@echo
	@echo "[ OBJECT MANAGEMENT SAMPLES ]"
	@echo "- CKM_AES_KWP_demo"
	@echo "- CKM_AES_KW_demo"
	@echo "- C_CopyObjects_demo"
	@echo "- C_CreateObject_demo"
	@echo "- C_DestroyObject_demo"
	@echo "- C_FindObjects_demo"
	@echo "- C_GetAttributeValue_demo"
	@echo "- C_SetAttributeValue_demo"
	@echo "- CreateKnownKeys"
	@echo "- UnwrapTemplates_demo"
	@echo
	@echo "[ MISCELLANEOUS SAMPLES ]"
	@echo "- C_GenerateRandom_demo"
	@echo "- C_GetMechanismList_Demo"
	@echo "- C_SeedRandom_demo"
	@echo "- Crypto_User_Login"
	@echo "- C_GetMechanismInfo_demo"
	@echo "- Usage_Limit_demo"
	@echo "- MultiThread_Signing_demo"
	@echo "- List_Available_Slots"
	@echo
	@echo "[ SAFENET EXTENSION SAMPLES ]"
	@echo "- Show_Partition_Policies"
	@echo "- CA_SIMExtract_demo"
	@echo "- CA_SIMInsert_demo"
	@echo "- Per_Key_Authorization_demo"
	@echo
	@echo "[ PQC SAMPLES ]"
	@echo "- CKM_HSS_sign_demo"
	@echo "- CKM_HSS_verify_demo"
	@echo "- CKM_HSS_KEY_PAIR_GEN_demo"
	@echo "- CKM_ML_DSA_KEY_PAIR_GEN_demo"
	@echo "- CKM_ML_KEM_KEY_PAIR_GEN_demo"
	@echo "- CKM_ML_DSA_Sign_Verify_demo"
	@echo "- CKM_HASH_ML_DSA_Sign_Verify_demo"
	@echo "- CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo"
	@echo "- CKM_ML_KEM_Encapsulate_Decapsulate_demo"


help:
	@echo
	@echo "Luna HSM | C_Samples | MAKE Help"
	@echo
	@echo "MAKE OPTIONS"
	@echo "------------"
	@echo
	@echo "- make               : Defaults to building all source files."
	@echo "- make all	    : Builds all sample codes."
	@echo "- make encryption    : Builds all encryption samples."
	@echo "- make signing       : Builds all signing samples."
	@echo "- make keygen        : Builds all samples for key generation."
	@echo "- make objmgmt       : Builds all object management samples."
	@echo "- make misc          : Builds all miscellaneous samples."
	@echo "- make sfntExtension : Builds all SafeNet Extension samples."
	@echo "- make pqc	    : Builds all PQC samples."
	@echo "- make clean         : Deletes all binaries."
	@echo "- make list_samples  : Displays the list of all available samples."
	@echo
	@echo
	@echo "You can also build a specific sample by providing the name of that sample without .C file extension. For example :-"
	@echo
	@echo "make CKM_AES_KEY_GEN_demo"
	@echo "make C_CreateObject_demo"
	@echo
