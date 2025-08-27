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




        OBJECTIVE : This sample demonstrates how to wrap a secret key using CKM_AES_KW mechanism.
	- Running this sample would generate two AES keys. One for wrapping and the other to be wrapped.
	- Wrapped key will later be unwrapped using the same wrapping key.
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


CK_BYTE iv[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}; // Initialization vector for CKM_AES_KW mechanism.
CK_BYTE *wrappedKey = NULL; // Stores the wrapped (encrypted key).
CK_OBJECT_HANDLE toBeWrapped = 0; // Handle number of the target key.
CK_OBJECT_HANDLE wrappingKey = 0; // Handle number of the wrapping key.
CK_OBJECT_HANDLE unwrappedKey = 0; // Handle number of the unwrapped key.



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



// This function generates a 256 bit AES key.
CK_OBJECT_HANDLE generateAESKey(const char *label)
{
        CK_MECHANISM mech = {CKM_AES_KEY_GEN};
        CK_BYTE *keyLabel = NULL;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ULONG keyLen = 32;
	CK_OBJECT_HANDLE objHandle = 0;

	keyLabel = (CK_BYTE*)malloc(strlen(label));
	strncpy(keyLabel, label, strlen(label));

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &no,                    sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &no,                    sizeof(CK_BBOOL)},
                {CKA_WRAP,              &yes,                   sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &yes,                   sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,                   sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &yes,                   sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,                    sizeof(CK_BBOOL)},
                {CKA_LABEL,             keyLabel,               strlen(keyLabel)},
                {CKA_VALUE_LEN,         &keyLen,                sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle),"C_GenerateKey");
	free(keyLabel);
        return objHandle;
}



// This function uses the wrapping key to wrap the target key
CK_ULONG wrapKey()
{
        CK_MECHANISM mech = {CKM_AES_KW, iv, sizeof(iv)};
	CK_ULONG encLen = 0;
        checkOperation(p11Func->C_WrapKey(hSession, &mech, wrappingKey, toBeWrapped, NULL_PTR, &encLen),"C_WrapKey");
        wrappedKey = (CK_BYTE*)calloc(encLen, 1);
        checkOperation(p11Func->C_WrapKey(hSession, &mech, wrappingKey, toBeWrapped, wrappedKey, &encLen),"C_WrapKey");
        return encLen;
}



// This function unwraps the wrapped key
void unwrapKey(CK_ULONG keyLen)
{
        CK_MECHANISM mech = {CKM_AES_KW, iv, sizeof(iv)};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG valueLen = 32;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
		{CKA_VALUE_LEN,		&valueLen,	sizeof(CK_ULONG)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_UnwrapKey(hSession, &mech, wrappingKey, wrappedKey, keyLen, attrib, attribLen, &unwrappedKey),"C_UnwrapKey");
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

	wrappingKey = generateAESKey("WRAPPING_KEY");
	printf("\n> Wrapping key generated. Handle : %lu.\n", wrappingKey);
	toBeWrapped = generateAESKey("TO_BE_WRAPPED");
	printf("\n> Key to be wrapped, generated. Handle : %lu.\n", toBeWrapped);
	CK_ULONG encLen = wrapKey();
	printf("\n> Key wrapped.\n");
	unwrapKey(encLen);
	printf("\n> Wrapped key unwrapped. Handle : %lu.\n", unwrappedKey);
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
