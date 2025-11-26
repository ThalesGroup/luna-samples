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
	- This sample demonstrates how to unwrap wrapped private key of type ML-DSA and ML-KEM into a Luna partition.
	- It requires firmware version 7.9.1 and Lunaclient 10.9.0 or later to execute.
	- The wrap private key is read from a file and unwrapped using the CKM_AES_KWP mechanism.
	- The filename of the file containing the wrappped private key is used as the label for the unwrapped private key.
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
CK_OBJECT_HANDLE hWrappingKey = 0; // stores the wrapping key handle.
CK_OBJECT_HANDLE hUnwrappedKey = 0; // stores the unwrapped key handle.
char *privKeyLabel = NULL; // stores the private key label.
char *wrappingKeyLabel = NULL; // stores the wrapping key label.
char *wrappedKeyFile = NULL; // stores the filename containing the wrapped key.
CK_BYTE iv[] = {0x1, 0x2, 0x3, 0x4};
CK_BYTE *wrappedKey = NULL;  // stores the wrapped key data.
CK_KEY_TYPE unwrappedKeyType = 0; // stores the type of key to unwrap.
CK_ULONG wrappedKeyLen = 0;
CK_ULONG privKeyLabelLen = 0;


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
	free(privKeyLabel);
	free(wrappingKeyLabel);
	free(wrappedKeyFile);
	free(wrappedKey);
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



// Reads the wrapped key file.
void readWrappedKeyFile()
{
	FILE *readFile;
	long fileSize;

	readFile = fopen(wrappedKeyFile, "rb");
	if(!readFile)
	{
		printf("Failed to read %s.\n", wrappedKeyFile);
		exit(1);
	}

	fseek(readFile, 0, SEEK_END);
	fileSize = ftell(readFile);
	wrappedKeyLen = fileSize;
	rewind(readFile);

	wrappedKey = (CK_BYTE*)malloc(fileSize);
	fread(wrappedKey, sizeof(CK_BYTE), fileSize, readFile);
	fclose(readFile);
	printf("\n> Wrapped key read from file.\n");
}



// Asks user to input the label of the wrapping key.
void inputLabels()
{
	int keyType = 0;
	char label[50];
	int len;

        printf("\n> Enter wrapping key label : ");
        fgets(label, sizeof(label), stdin);
        len = strlen(label);
        wrappingKeyLabel = (CK_UTF8CHAR*)malloc(len);
        strncpy(wrappingKeyLabel, label, len);
        wrappingKeyLabel[len] = '\0';


	printf("\n> Type of key to unwrap : \n");
	printf("  --> 1. ML-DSA.\n");
	printf("  --> 2. ML-KEM.\n");
	printf("      Key type : ");
	scanf("%d", &keyType);
	if(keyType==1)
		unwrappedKeyType = CKK_ML_DSA;
	else if(keyType==2)
		unwrappedKeyType = CKK_ML_KEM;
	else
	{
		printf("\nInvalid option.\n");
		disconnectFromLunaSlot();
		freeMem();
		exit(1);
	}
}




// This function finds the wrapping AES key.
void findWrappingKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE handles[1];
	CK_ULONG objectCount = 0;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,                     &objClass,              sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,                  &keyType,               sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,                     wrappingKeyLabel,       strlen(wrappingKeyLabel)-1}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, handles, 1, &objectCount), "C_FindObjects");
	if(objectCount==0)
	{
		printf("\n> Wrapping key not found.\n");
		disconnectFromLunaSlot();
		freeMem();
		exit(1);
	}
	else
	{
		hWrappingKey = handles[0];
		printf("\n> Wrapping key found. Handle : %lu\n", hWrappingKey);
	}
}



// This function unwraps the wrapped private key
void unwrapPrivateKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_MECHANISM mech = {CKM_AES_KWP, iv, sizeof(iv)};
	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_TOKEN,             &yes,           	sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &yes,           	sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,         &yes,           	sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,       &yes,           	sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,        &yes,           	sizeof(CK_BBOOL)},
		{CKA_SIGN,              &yes,           	sizeof(CK_BBOOL)},
		{CKA_DECRYPT,           &yes,           	sizeof(CK_BBOOL)},
		{CKA_CLASS,             &objClass,      	sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,          &unwrappedKeyType,      sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,		privKeyLabel,		privKeyLabelLen}
	};
	CK_ULONG attribLen = sizeof(attrib)/sizeof(*attrib);

	checkOperation(p11Func->C_UnwrapKey(hSession, &mech, hWrappingKey, wrappedKey, wrappedKeyLen, attrib, attribLen, &hUnwrappedKey), "C_UnwrapKey");
	printf("\n> Private key unwrapped as handle : %lu.\n", hUnwrappedKey);
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
        printf("\nUsage :-\n");
        printf("%s <slot_number> <crypto_officer_password> <wrapped_private_key_file>\n\n", exeName);
}




int main(int argc, char **argv[])
{
	int len = 0;
	printf("\n%s\n", (char*)argv[0]);
	if(argc<4) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);

	len = strlen((const char*)argv[2]);
	slotPin = (CK_BYTE*)malloc(len);
	strncpy(slotPin, (char*)argv[2], len);

	len = strlen((const char*)argv[3]);
	wrappedKeyFile = (char*)malloc(len);
	strncpy(wrappedKeyFile, (char*)argv[3], len);

	privKeyLabelLen = len + 6;
	privKeyLabel = (char*)malloc(len + 6);
	strncpy(privKeyLabel, wrappedKeyFile, len - 4);
	len = 10;
	strncat(privKeyLabel, "-unwrapped", len);

	loadLunaLibrary();
	connectToLunaSlot();
	readWrappedKeyFile();
	inputLabels();
	findWrappingKey();
	unwrapPrivateKey();

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}

