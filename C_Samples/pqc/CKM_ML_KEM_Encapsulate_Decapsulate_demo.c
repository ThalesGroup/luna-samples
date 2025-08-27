        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The " luna-samples" project is provided under the MIT license (see the         *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2025 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

	OBJECTIVE :
	- This sample demonstrates how to use the C_EncapsulateKey and C_DecapsulateKey functions with an ML-KEM key pair.
	- C_EncapsulateKey function encapsulates an AES key and produces a CipherText.
	- C_DecapsulateKey function then uses the CipherText to decapsulate the AES key.
	- It requires firmware version 7.9.0 to execute and does not utilise the PQC-FM toolkit.
	- Luna Client 10.9.0 must also be installed.
*/

#include <stdio.h>
#include <cryptoki_v2.h>
#include <sfnt_extensions.h>
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
CK_SFNT_CA_FUNCTION_LIST *sfntFunc = NULL;

CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID slotId = 0; // slot id
CK_BYTE *slotPin = NULL; // slot password
CK_ML_KEM_PARAMETER_SET_TYPE paramType = 0;
CK_OBJECT_HANDLE objHandlePub = 0;
CK_OBJECT_HANDLE objHandlePri = 0;
CK_BYTE *cipherText = NULL;
CK_ULONG cipherTextLen = 0;
CK_OBJECT_HANDLE encapsulatedKey = 0;
CK_OBJECT_HANDLE decapsulatedKey = 0;



// Loads Luna cryptoki library
void loadLunaLibrary()
{
        CK_C_GetFunctionList C_GetFunctionList = NULL;
	CK_CA_GetFunctionList CA_GetFunctionList = NULL;

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
		CA_GetFunctionList = (CK_CA_GetFunctionList)dlsym(libHandle, "CA_GetFunctionList");
        #else
                C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList"); // Loads symbols on Windows.
		CA_GetFunctionList = (CK_CA_GetFunctionList)GetProcAddress(libHandle, "CA_GetFunctionList");
        #endif

        C_GetFunctionList(&p11Func); // Gets the list of all Pkcs11 Functions.
	CA_GetFunctionList(&sfntFunc); // Gets the list of all SFNT CA functions.

        if(p11Func==NULL || sfntFunc==NULL)
        {
                printf("Failed to load required functions.\n");
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
	free(cipherText);
}



// Checks if a P11 operation was a success or failure
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		printf("%s failed with Ox%lX\n\n",message,rv);
		p11Func->C_Finalize(NULL_PTR);
		freeMem();
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



// Asks for the ML-KEM parameter to use and sets the CipherTextLen based on the parameter.
void inputParameter()
{
        int param;
        printf("  --> ML-KEM parameter\n");
        printf("      - MLKEM-512 ...... 1\n");
        printf("      - MLKEM-768 ...... 2\n");
        printf("      - MLKEM-1024 ..... 3\n");
        printf("        Parameter : ");
        scanf("%d", &param);
        switch(param)
        {
                case 1:
			paramType = CKP_ML_KEM_512;
			cipherTextLen = 768;
			break;
                case 2:
			paramType = CKP_ML_KEM_768;
			cipherTextLen = 1088;
			break;
                case 3:
			paramType = CKP_ML_KEM_1024;
			cipherTextLen = 1568;
			break;
                default: printf("Invalid parameter\n"); exit(0);
        }
}


// This function generates ML-KEM key pair.
void generateMLKEMKeyPair()
{
	inputParameter();
        CK_MECHANISM mech = {CKM_ML_KEM_KEY_PAIR_GEN};
        CK_BBOOL yes = CK_TRUE;

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_ENCAPSULATE,       &yes,           sizeof(CK_BBOOL)},
		{CKA_PARAMETER_SET,	&paramType,	sizeof(CK_ML_KEM_PARAMETER_SET_TYPE)}
        };
        CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
		{CKA_PARAMETER_SET,     &paramType,     sizeof(CK_ML_KEM_PARAMETER_SET_TYPE)},
		{CKA_DECAPSULATE,	&yes,		sizeof(CK_BBOOL)},
        };
        CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri), "C_GenerateKeyPair");
	printf("\n> ML-KEM keypair generated.\n");
	printf("  --> Private key handle : %lu\n", objHandlePri);
	printf("  --> Public key handle : %lu\n", objHandlePub);
}



// This function encapsulates an AES-256 key.
void encapsulateAesKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG keySize = 32;
	CK_MECHANISM mech = {CKM_ML_KEM};
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,		&objClass,	sizeof(CK_OBJECT_CLASS)},
		{CKA_ENCRYPT,		&yes,		sizeof(CK_BBOOL)},
		{CKA_DECRYPT,		&yes,		sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,		&keyType,	sizeof(CK_KEY_TYPE)},
		{CKA_VALUE_LEN,		&keySize,	sizeof(CK_ULONG)}
	};
	CK_ULONG attribLen = sizeof(attrib)/sizeof(*attrib);
	cipherText = (CK_BYTE*)malloc(cipherTextLen);
	checkOperation(sfntFunc->CA_EncapsulateKey(hSession, &mech, objHandlePub, attrib, attribLen, cipherText, &cipherTextLen, &encapsulatedKey), "CA_EncapsulateKey");

        printf("\n> AES-Key encapsulated.\n");
	printf("  --> CipherText length : %lu\n", cipherTextLen);
        printf("  --> Encapsulated Key Handle : %lu\n", encapsulatedKey);
}



// This function decapsulate the AES-256 key from the ciphertext.
void decapsulateAesKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no  = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG keySize = 32;
	CK_MECHANISM mech = {CKM_ML_KEM};
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)},
                {CKA_VALUE_LEN,         &keySize,       sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib)/sizeof(*attrib);
	checkOperation(sfntFunc->CA_DecapsulateKey(hSession, &mech, objHandlePri, attrib, attribLen, cipherText, cipherTextLen, &decapsulatedKey), "CA_DecapsulateKey");

        printf("\n> AES-Key decapsulated.\n");
        printf("  --> Decapsulated key handle : %lu\n", decapsulatedKey);
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
	generateMLKEMKeyPair();
	encapsulateAesKey();
	decapsulateAesKey();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
