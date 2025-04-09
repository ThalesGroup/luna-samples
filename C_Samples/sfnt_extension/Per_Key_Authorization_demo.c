        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                       	 *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************



        OBJECTIVE :
	- This menu-driven sample demonstrates the usage of the Per Key Authorization (PKA) feature.
	- A version-1 partition is required to execute this code.
	- The sample allows you to either generate an AES-128 key or load an existing AES key with associated authorization data.
	- The encryption key can then be used to perform encryption operations.
	- The encryption test will succeed if the key is authorized; otherwise, it will fail.
	- After three consecutive failures, the key will be deactivated.
	- A deactivated key can be reactivated by resetting its authorization data.
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
CK_SFNT_CA_FUNCTION_LIST *sfntFunc = NULL;

CK_SESSION_HANDLE hSession = 0;
CK_SESSION_HANDLE encSession = 0; // session handle used for authorizing encryption.

CK_SLOT_ID slotId = 0; // slot id
CK_BYTE *slotPin = NULL; // slot password
CK_OBJECT_HANDLE objHandle = 0; // object handle of the encryption key.
CK_BYTE keyId[] = {0xcd, 0x81, 0xc4, 0xe4, 0x73, 0x20, 0x03, 0x61, 0x08, 0xbf, 0x17, 0xf3, 0x06, 0x0f, 0xf2, 0x01}; // for CKA-ID.
char *keyLabel = NULL; // stores label of the encryption key.
char *authData = NULL; // stores the authorization data.



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
	CA_GetFunctionList(&sfntFunc);

	if(p11Func==NULL)
	{
		printf("Failed to load P11 functions.\n");
		exit(1);
	}

	if(sfntFunc==NULL)
	{
		printf("Failed to load SFNT functions.\n");
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
	free(slotPin);
}



// Disconnects from Luna slot (C_Logout, C_CloseSession and C_Finalize)
void disconnectFromLunaSlot()
{
	checkOperation(p11Func->C_Logout(hSession), "C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from Luna slot.\n\n");
}



// Used for key label input.
void inputKeyLabel()
{
	char *input = NULL;
	size_t str_size = 0;
	printf("\t - Key label                  : ");
	getline(&input, &str_size, stdin);
	input[strcspn(input, "\n")] = '\0';
	keyLabel = (char*)malloc(strlen(input)+1);
	strncpy(keyLabel, input, strlen(input)+1);
}



// Used for auth data input.
void inputAuthData()
{
	char *input = NULL;
	size_t str_size = 0;
        printf("\t - Authorization Data (Hex)   : ");
	getline(&input, &str_size, stdin);
	input[strcspn(input, "\n")] = '\0';
	authData = (char*)malloc(strlen(input)+1);
	strncpy(authData, input, strlen(input)+1);
}



// This function generates an AES key with user defined attributes and authorization data for PKA.
void generateAESKey()
{
        CK_MECHANISM mech = {CKM_AES_KEY_GEN};
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ULONG keyLen = 16;

	inputKeyLabel();
	inputAuthData();

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &yes,                   sizeof(CK_BBOOL)},
		{CKA_ID,		&keyId,			sizeof(keyId)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,                   sizeof(CK_BBOOL)},
		{CKA_SIGN,		&no,			sizeof(CK_BBOOL)},
		{CKA_VERIFY,		&no,			sizeof(CK_BBOOL)},
                {CKA_WRAP,              &no,                    sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &no,                    sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClass,              sizeof(CK_OBJECT_CLASS)},
                {CKA_SENSITIVE,         &yes,                   sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,                    sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &yes,                   sizeof(CK_BBOOL)},
                {CKA_LABEL,             keyLabel,               strlen(keyLabel)},
		{CKA_AUTH_DATA,		authData,		strlen(authData)},
                {CKA_VALUE_LEN,         &keyLen,                sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle),"C_GenerateKey");
        printf("\n> AES Key generated. Handle : %lu\n", objHandle);
	free(keyLabel);
	free(authData);
}



// Loads an existing AES key with an associated auth-data.
CK_OBJECT_HANDLE loadExistingKey()
{
	CK_ATTRIBUTE attrib[6];
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL yes = CK_TRUE;
	CK_ULONG objCount = 0;
	CK_OBJECT_HANDLE objects[1];

	inputKeyLabel();

	attrib[0] = (CK_ATTRIBUTE){CKA_LABEL,		keyLabel,	strlen(keyLabel)};
	attrib[1] = (CK_ATTRIBUTE){CKA_ID,		&keyId,		sizeof(keyId)};
	attrib[2] = (CK_ATTRIBUTE){CKA_TOKEN,		&yes,		sizeof(CK_BBOOL)};
	attrib[3] = (CK_ATTRIBUTE){CKA_PRIVATE,		&yes,		sizeof(CK_BBOOL)};
	attrib[4] = (CK_ATTRIBUTE){CKA_CLASS,		&objClass,	sizeof(CK_OBJECT_CLASS)};
	attrib[5] = (CK_ATTRIBUTE){CKA_KEY_TYPE,	&keyType,	sizeof(CK_KEY_TYPE)};

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, 6), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, objects, 1, &objCount), "C_FindObjects");
	checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
	free(keyLabel);

	if(objCount==0)
	{
		printf("%s key not found.\n", keyLabel);
		return 0;
	}
	else
	{
		return objects[0];
	}
}



// Authorizes a session to use an AES-key for encryption.
void authorizeKey()
{
	CK_RV rv = CKR_OK;
	if(objHandle==0) {
		printf("\nNothing to authorize. Generate an encryption or load an existing key.\n");
		return;
	}

	inputAuthData();
	rv = sfntFunc->CA_AuthorizeKey(encSession, objHandle, authData, strlen(authData));

	if(rv!=CKR_OK) {
		printf("\nFailed to authorize key : Ox%lX.\n", rv);
		return;
	}

	printf("Key is now authorized.\n");
	free(authData);
}



// Resets authorization data and key status.
void resetAuthorization()
{
	if(objHandle==0) {
		printf("\nNothing to reset. Generate an encryption or load an existing key.\n");
		return;
	}

	inputAuthData();
	checkOperation(sfntFunc->CA_ResetAuthorizationData(encSession, objHandle, authData, strlen(authData)), "CA_ResetAuthorizationData");
	printf("Authorization data has been reset.\n");
	free(authData);
}



// Closes the session that was previously authorized to perform encryption.
void revokeAuthorization()
{
	checkOperation(p11Func->C_CloseSession(encSession), "C_CloseSession");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &encSession), "C_OpenSession");
	printf("\nAccess revoked.\n");
}



// Displays the status of an encryption key.
void showKeyStatus()
{
	CK_KEY_STATUS keyStatus;
	CK_ULONG failedAuth;
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_KEY_STATUS,		&keyStatus,	sizeof(CK_KEY_STATUS)},
		{CKA_FAILED_KEY_AUTH_COUNT,	&failedAuth,	sizeof(CK_ULONG)}
	};

	if(objHandle==0) {
		printf("\nEncryption key not loaded.\n");
		return;
	}

	checkOperation(p11Func->C_GetAttributeValue(hSession, objHandle, attrib, 2), "C_GetAttributeValue");
	printf("\nFailed authentication Limit    : %d", keyStatus.failedAuthCountLimit);
	printf("\nFailed authentication attempts : %ld", failedAuth);
	printf("\nFlag : ");
	switch(keyStatus.flags)
	{
		case 0x01 : printf("CK_KEY_STATUS_F_AUTH_DATA_SET");
		break;
		case 0x02 : printf("CK_KEY_STATUS_F_LOCKED_DUE_TO_FAILED_AUTH");
		break;
		case 0x03 : printf("CK_KEY_STATUS_F_LOCKED_DUE_TO_DATE");
		break;
		case 0x04 : printf("CK_KEY_STATUS_F_LOCKED_DUE_TO_DES3_BLOCK_COUNTER");
		break;
		case 0x05 : printf("CK_KEY_STATUS_F_LOCKED_DUE_TO_USAGE_COUNTER");
		break;
	}
	printf("\n");
}



// Performs encryption, fails if not authorized.
void encryptionTest()
{
	CK_BYTE iv[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
	char rawData[] = "Earth is the third planet of our solar System";
	CK_BYTE *encrypted = NULL;
	CK_ULONG encLen = 0;
	CK_RV rv = 0;

	CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, sizeof(iv)};

	if(objHandle==0) {
		printf("\nEncryption key not loaded.\n");
		return;
	}

	checkOperation(p11Func->C_EncryptInit(encSession, &mech, objHandle), "C_EncryptInit");
	rv = p11Func->C_Encrypt(encSession, rawData, sizeof(rawData)-1, NULL, &encLen);
	if(rv==CKR_KEY_NOT_AUTHORIZED)
	{
		printf("\nERROR: \tYou're not authorized to use this key.\n\tPlease authorize it and try again.\n");
		return;
	}
	else if(rv==CKR_KEY_NOT_ACTIVE)
	{
		printf("\nERROR: \tThis key is not active.");
	}
	else
	{
		encrypted = (CK_BYTE*)malloc(encLen);
		checkOperation(p11Func->C_Encrypt(encSession, rawData, sizeof(rawData)-1, encrypted, &encLen), "C_Encrypt");
		printf("Encryption worked.\n");
	}
}



// Prints the syntax for executing this code.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_office_password>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	int choice;
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
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &encSession), "C_OpenSession");
	do
	{
		printf("\n\nPer Key Authorization Demo\n");
		printf("1. Generate a new AES key.\n");
		printf("2. Load an existing AES key.\n");
		printf("3. Authorize the key to perform encryption.\n");
		printf("4. Revoke Authorization\n");
		printf("5. Show key status.\n");
		printf("6. Reset key status.\n");
		printf("7. Perform Encryption Test. \n");
		printf("0. Exit.\n");
		printf("Choice : ");
		scanf("%d", &choice); getchar();
		switch(choice)
		{
			case 1: generateAESKey();
			break;
			case 2: objHandle = loadExistingKey();
			break;
			case 3: authorizeKey();
			break;
			case 4: revokeAuthorization();
			break;
			case 5: showKeyStatus();
			break;
			case 6: resetAuthorization();
			break;
			case 7: encryptionTest();
			break;
			case 0:
			default: printf("Exiting...\n");
		}
	}while(choice!=0);
	checkOperation(p11Func->C_CloseSession(encSession), "C_CloseSession");
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
