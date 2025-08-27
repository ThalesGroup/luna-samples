        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************



	OBJECTIVE :-
	- This sample demonstrates how to import a known secret key into Luna HSM.
	- A known secret key is a secret key whose key value is available in plaintext.
	- Luna HSMs do not allow secret keys to be imported in plaintext, so the solution is as follows:
		1. Read the plain secret key as binary data.
	    	2. Generate an ephemeral secret key and use it to encrypt the plaintext secret.
	    	3. Unwrap the encrypted secret key into the Luna HSM as a secret key.

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

CK_OBJECT_HANDLE wrappingKey = 0; // Handle number of the wrapping key.
CK_BYTE knownKey[] = {0x10, 0xaa, 0x32, 0x56, 0xa1, 0x87, 0xF1, 0x63, 0x82, 0xd3, 0x4d, 0x95, 0xac, 0x76, 0x01, 0x63}; // 16 bytes of plain key value.
CK_BYTE *encryptedKey = NULL; // used for storing encrypted known key.
CK_BYTE iv[8]; // used for storing hsm generated IV.



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



// This function generates an AES-128 key
void generateAESKey()
{
	CK_MECHANISM mech = {CKM_AES_KEY_GEN};
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	CK_ULONG keyLen = 16;

	CK_ATTRIBUTE attrib[] = 
	{
		{CKA_TOKEN,		&no,		sizeof(CK_BBOOL)},
		{CKA_PRIVATE,		&yes,		sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,		&yes,		sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,	&no,		sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,	&no,		sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,		&yes,		sizeof(CK_BBOOL)},
		{CKA_DECRYPT,		&no,		sizeof(CK_BBOOL)},
		{CKA_WRAP,		&no,		sizeof(CK_BBOOL)},
		{CKA_UNWRAP,		&yes,		sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN,		&keyLen,	sizeof(CK_ULONG)}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
	checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &wrappingKey), "C_GenerateKey");
	printf("\n> AES key generated. Handle : %lu.\n", wrappingKey);
}



// This function generates IV for encryption using Luna RNG.
void generateIV()
{
	checkOperation(p11Func->C_GenerateRandom(hSession, iv, sizeof(iv)), "C_GenerateRandom");
	printf("\n> IV Generated for encryption.\n");
}



// This function will encrypt the known plain key using the generates AES key.
CK_ULONG encryptKeyBytes()
{
        CK_MECHANISM mech = {CKM_AES_KW, iv, sizeof(iv)};
        CK_ULONG encLen = 0;
        checkOperation(p11Func->C_EncryptInit(hSession, &mech, wrappingKey),"C_EncryptInit");
        checkOperation(p11Func->C_Encrypt(hSession, knownKey, sizeof(knownKey), NULL_PTR, &encLen),"C_Encrypt");
        encryptedKey = (CK_BYTE*)calloc(encLen, 1);
        checkOperation(p11Func->C_Encrypt(hSession, knownKey, sizeof(knownKey), encryptedKey, &encLen),"C_Encrypt");
        printf("\n> Plain key encrypted.\n");
 	return encLen;
}



// This function will unwrap the encrypted keybytes into an actual key
void unwrapKey(CK_ULONG encKeyLen)
{
        CK_MECHANISM mech = {CKM_AES_KW, iv, sizeof(iv)};
        CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ULONG keyLen = 16;
        CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG unwrappedKey = 0;

        CK_ATTRIBUTE attrib[] =
        {
		{CKA_TOKEN,		&no,		sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,	&no,		sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,	&no,		sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
		{CKA_WRAP,		&no,		sizeof(CK_BBOOL)},
		{CKA_UNWRAP,		&no,		sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)},
		{CKA_VALUE_LEN,		&keyLen,	sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_UnwrapKey(hSession, &mech, wrappingKey, encryptedKey, encKeyLen, attrib, attribLen, &unwrappedKey),"C_UnwrapKey");
        printf("\n> Encrypted key unwrapped as handle : %lu.\n", unwrappedKey);
}



// Prints the syntax for executing this code.
void usage(const char exeName[30])
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
	generateAESKey();
	generateIV();
	unwrapKey(encryptKeyBytes());
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
