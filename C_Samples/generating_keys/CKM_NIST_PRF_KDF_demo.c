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



	OBJECTIVE : This sample demonstrates how to derive a key using CKM_NIST_PRF_KDF mechanism.
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
CK_BYTE *baseKeyLabel = NULL; // Label of the base AES key.
CK_OBJECT_HANDLE hDerived = 0;
CK_OBJECT_HANDLE hMaster = 0;
CK_PRF_KDF_PARAMS param;



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
	free(baseKeyLabel);
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



// This function finds the base key to be used for key derivation.
void findBaseKey()
{
        CK_BBOOL yes = CK_TRUE;
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE handles[1];
	CK_ULONG objectCount = 0;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_PRIVATE,   	&yes,           sizeof(CK_BBOOL)},
                {CKA_TOKEN,             &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,		&keyType,	sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,		baseKeyLabel,	strlen(baseKeyLabel)}
        };

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, 5), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, handles, 1, &objectCount), "C_FindObjects");
	if(objectCount==0)
	{
		printf("\nBase key [ %s ], not found.\n", baseKeyLabel);
	}
	else
	{
		hMaster = handles[0];
		printf("  --> Base key found. Handle : %lu\n", hMaster);
	}
}


// Initialize KDF-PRF params.
void initParam()
{
	static CK_BYTE paramLabel[] = "12345678";
	static CK_BYTE context[] = "12345678";

	param.prfType = CK_NIST_PRF_KDF_AES_CMAC;
	param.pLabel = paramLabel;
	param.ulLabelLen = sizeof(paramLabel)-1;
	param.pContext = context;
	param.ulContextLen = sizeof(context)-1;
	param.ulCounter = 1;
	param.ulEncodingScheme = LUNA_PRF_KDF_ENCODING_SCHEME_1;
}



// This function derives an AES key from the base key.
void deriveKey()
{
	initParam();

        CK_MECHANISM mech = {CKM_NIST_PRF_KDF, &param, sizeof(param)};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_KEY_TYPE keyType = CKK_AES;
	CK_BYTE *keyLabel = NULL;
        CK_ULONG keyLen = 32;

	// Setting label as key-derived-from-<base_key_label>
	keyLabel = (CK_BYTE*)malloc(17+strlen(baseKeyLabel));
	strncpy(keyLabel, "key-derived-from-", 17);
	strncat(keyLabel, baseKeyLabel, strlen(baseKeyLabel));

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &yes,           sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_WRAP,              &no,            sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &no,            sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,        sizeof(CK_ULONG)},
		{CKA_LABEL,		keyLabel,	strlen((const char*)keyLabel)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)}
        };
        CK_ULONG attribLen = sizeof(attrib)/sizeof(*attrib);
        checkOperation(p11Func->C_DeriveKey(hSession, &mech, hMaster, attrib, attribLen, &hDerived), "C_DeriveKey");
        printf("\n> AES key derived.\n");
	printf("  --> Handle : %lu\n", hDerived);
	free(keyLabel);
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_office_password> <base_AES-KEY_label>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	printf("\n%s\n", (char*)argv[0]);
	if(argc<4) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);
	slotPin = (CK_BYTE*)malloc(strlen((const char*)argv[2]));
	strncpy(slotPin, (char*)argv[2], strlen((const char*)argv[2]));
	baseKeyLabel = (CK_BYTE*)malloc(strlen((const char*)argv[3]));
	strncpy(baseKeyLabel, (char*)argv[3], strlen((const char*)argv[3]));

	loadLunaLibrary();
	connectToLunaSlot();
	findBaseKey();

	// Exit if the base-key wasn't found.
	if(hMaster!=0)
		deriveKey();

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
