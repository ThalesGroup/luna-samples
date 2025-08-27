        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The " luna-samples" project is provided under the MIT license (see the         *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************



	OBJECTIVE :-
	This sample demonstrates the usage of CKM_ECDH1_DERIVE for Key Exchange. It performs the following actions :-
	>> Party A and Party B generate their own ECDSA keypair.
	>> Both parties exchange their public keys.
	>> Party A derives an AES-256 Key using the public key received from Party B.
	>> Party B derives an AES-256 Key using the public key received from Party A.
	>> Party A encrypts some data using its own derived Key.
	>> Party B decrypts the encrypted data from Party A using its own derived Key.
*/

#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>


// Windows and Linux OS uses different header files for loading libraries.
#ifdef OS_UNIX
        #include <dlfcn.h> // For Unix/Linux OS.
#else
        #include <windows.h> // For Windows OS.
#endif


// Windows uses HINSTANCE for storing library handles.
#ifdef OS_UNIX
        void *libHandle = 0; // Library handle for Unix/Linux
#else
        HINSTANCE libHandle = 0; //Library handle for Windows.
#endif



CK_FUNCTION_LIST *p11Func = NULL;
CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID slotId = 0; // slot id
CK_BYTE *slotPin = NULL; // slot password

CK_OBJECT_HANDLE partyAPub = 0; // Public key of Party A.
CK_OBJECT_HANDLE partyAPri = 0; // Private key of Party A.
CK_OBJECT_HANDLE partyBPub = 0; // Public key of Party B.
CK_OBJECT_HANDLE partyBPri = 0; // Private key of Party B.
CK_OBJECT_HANDLE derivedKeyA = 0; // Key derived by Party A.
CK_OBJECT_HANDLE derivedKeyB = 0; // Key derived by Party B.

CK_BYTE *ecPoint = NULL; // for storing public key.
CK_ULONG ecPointLen = 0; // length of public key.
CK_BYTE plainData[] = "Earth is the third planet of our Solar System. This planet is also known as the blue planet."; // raw data for encryption.
CK_BYTE *encryptedData = NULL; // for storing encrypted data.
CK_BYTE *decryptedData = NULL; // for storing decrypted data.
CK_BYTE iv[] = "1234abcd1234abcd"; // IV for encryption.
CK_ULONG encLen = 0; // length of encrypted data.



// Loads Luna cryptoki library
void loadLunaLibrary()
{
        CK_C_GetFunctionList C_GetFunctionList = NULL;

        char *libPath = getenv("P11_LIB"); // P11_LIB is the complete path of Cryptoki library.
        if(libPath==NULL)
        {
                printf("P11_LIB environment variable not set.\n");
                printf("\n > On Unix/Linux :-\n");
                printf("export P11_LIB=<PATH_TO_CRYPTOKI>");
                printf("\n\n > On Windows :-\n");
                printf("set P11_LIB=<PATH_TO_CRYPTOKI>");
                printf("\n\nExample :-");
                printf("\nexport P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so");
                printf("\nset P11_LIB=C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll\n\n");
                exit(1);
        }


        #ifdef OS_UNIX
                libHandle = dlopen(libPath, RTLD_NOW); // Loads shared library on Unix/Linux.
        #else
                libHandle = LoadLibrary(libPath); // Loads shared library on Windows.
        #endif
        if(!libHandle)
        {
                printf("Failed to load Luna library from path : %s\n", libPath);
                exit(1);
        }


        #ifdef OS_UNIX
            C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle, "C_GetFunctionList"); // Loads symbols on Unix/Linux
        #else
                C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList"); // Loads symbols on Windows.
        #endif

        C_GetFunctionList(&p11Func); // Gets the list of all Pkcs11 Functions.
        if(p11Func==NULL)
        {
                printf("Failed to load P11 functions.\n");
                exit(1);
        }

        printf ("\n> P11 library loaded.\n");
        printf ("  --> %s\n", libPath);
}



// Always a good idea to free up some memory before exiting.
void freeMem()
{
        #ifdef OS_UNIX
                dlclose(libHandle); // Close library handle on Unix/Linux
        #else
                FreeLibrary(libHandle); // Close library handle on Windows.
        #endif
        free(slotPin);
	free(encryptedData);
	free(decryptedData);
	free(ecPoint);
}



// Checks if a P11 operation was a success or failure
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		printf("%s failed with Ox%lX\n\n",message,rv);
		p11Func->C_Finalize(NULL_PTR);
		exit(1);
	}
}



// Connects to a Luna slot (C_Initialize, C_OpenSession, C_Login)
void connectToLunaSlot()
{
	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &hSession), "C_OpenSession");
	checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen(slotPin)), "C_Login");
	printf("\n> Connected to Luna.\n");
	printf("  --> SLOT ID : %ld.\n", slotId);
	printf("  --> SESSION ID : %ld.\n", hSession);
}



// Disconnects from Luna slot (C_Logout, C_CloseSession and C_Finalize)
void disconnectFromLunaSlot()
{
	checkOperation(p11Func->C_Logout(hSession), "C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from Luna slot.\n\n");
}



// This function generates ECDSA keypair.
void generateECKeys(CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR priKey)
{
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN};
        CK_BYTE param[] = {0x06,0x05,0x2B,0x81,0x04,0x00,0x22};

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,                     &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,                   &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,                   &yes,                   sizeof(CK_BBOOL)},
                {CKA_VERIFY,                    &yes,                   sizeof(CK_BBOOL)},
                {CKA_EC_PARAMS,                 &param,                 sizeof(param)}
        };
        CK_ULONG attribLenPub = sizeof(attribPub)/sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,                     &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,                   &yes,                   sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,                 &yes,                   sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,                &no,                    sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,               &no,                    sizeof(CK_BBOOL)},
                {CKA_DECRYPT,                   &yes,                   sizeof(CK_BBOOL)},
                {CKA_SIGN,                      &yes,                   sizeof(CK_BBOOL)},
                {CKA_DERIVE,                    &yes,                   sizeof(CK_BBOOL)}
        };
        CK_ULONG attribLenPri = sizeof(attribPri) /  sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, pubKey, priKey),"C_GenerateKeyPair");
}



// This function extracts the public key
void extractPublicKey(CK_OBJECT_HANDLE hPublic)
{
        CK_ATTRIBUTE attrib[] = {CKA_EC_POINT, NULL, 0};
        checkOperation(p11Func->C_GetAttributeValue(hSession, hPublic, attrib, 1),"C_GetAttributeValue");
        ecPointLen = attrib[0].ulValueLen;
        ecPoint = (CK_BYTE*)calloc(ecPointLen, 1);
        attrib[0].pValue = ecPoint;
        checkOperation(p11Func->C_GetAttributeValue(hSession, hPublic, attrib, 1),"C_GetAttributeValue");
}



// This function derives an AES key.
void deriveSecretKey(CK_OBJECT_HANDLE partyAPri, CK_OBJECT_HANDLE_PTR derived)
{
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ULONG keyLen = 32;
	CK_BYTE sharedData[] = "0011235813213455";
        CK_ECDH1_DERIVE_PARAMS params = {CKD_SHA1_KDF, sizeof(sharedData), sharedData, ecPointLen, ecPoint};
        CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &params, sizeof(params)};
        CK_KEY_TYPE objType = CKK_AES;
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_DERIVE,            &no,            sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,        sizeof(CK_ULONG)},
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
                {CKA_KEY_TYPE,          &objType,       sizeof(CK_KEY_TYPE)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_DeriveKey(hSession, &mech, partyAPri, attrib, attribLen, derived),"C_DeriveKey");
}



// This function will encrypt a plain data using the derived Key of party A
void encryptData()
{
        CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, sizeof(iv)-1};

        checkOperation(p11Func->C_EncryptInit(hSession, &mech, derivedKeyA),"C_EncryptInit");
        checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, NULL, &encLen), "C_Encrypt");
        encryptedData = (CK_BYTE*)calloc(encLen, 1);
        checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, encryptedData, &encLen), "C_Encrypt");
}



// This function will decrypt the encrypted data from Party A using the derived Key of party B
void decryptData()
{
        CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, sizeof(iv)-1};
        CK_ULONG decLen = 0;

        checkOperation(p11Func->C_DecryptInit(hSession, &mech, derivedKeyB), "C_DecryptInit");
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, NULL, &decLen), "C_Decrypt");
        decryptedData = (CK_BYTE*)calloc(decLen, 1);
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, decryptedData, &decLen), "C_Decrypt");
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	printf("\n%s\n", (char*)argv[0]);
	if(argc<3) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);
	slotPin = (CK_BYTE*)malloc(strlen((const char*)argv[2]));
	strncpy(slotPin, (char*)argv[2], strlen((const char*)argv[2]));

	loadLunaLibrary();
	connectToLunaSlot();

	generateECKeys(&partyAPub, &partyAPri);
	printf("\n> EC KeyPair generated for Party A.\n");
	printf("  --> Private Key Handle : %lu\n", partyAPri);
	printf("  --> Public Key Handle : %lu\n", partyAPub);

	generateECKeys(&partyBPub, &partyBPri);
        printf("\n> EC KeyPair generated for Party B.\n");
        printf("  --> Private Key Handle : %lu\n", partyBPri);
        printf("  --> Public Key Handle : %lu\n", partyBPub);

	extractPublicKey(partyBPub);
	printf("\n> Public key extracted for Party A.\n");
	deriveSecretKey(partyAPri, &derivedKeyA);
	printf("\n> Secret key derived for Party A.\n");
	printf("  --> Secret Key Handle A : %lu\n", derivedKeyA);

	extractPublicKey(partyAPub);
        printf("\n> Public Key extracted for Party B.\n");
        deriveSecretKey(partyBPri, &derivedKeyB);
        printf("\n> Secret key derived for Party B\n");
        printf("  --> Secret Key Handle B : %lu\n", derivedKeyB);

        encryptData();
        printf("\n> Party A has encrypted some data for Party B.");
        decryptData();
        printf("\n> Party B has decrypted the data received from Party A.\n\n");

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
