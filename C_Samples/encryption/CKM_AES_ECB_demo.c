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





        OBJECTIVE : This sample demonstrates how to encrypt and decrypt using CKM_AES_ECB mechanism.
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

CK_OBJECT_HANDLE hObject = 0;
CK_BYTE *encryptedData = NULL;
CK_BYTE *decryptedData = NULL;
CK_BYTE plainText[] = "12345678123456781234567812345678";



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



// This function generates AES-256 key for the purpose for encryption and decryption.
void generateAESKey()
{
        CK_MECHANISM mech = {CKM_AES_KEY_GEN};
        CK_ULONG keyLen = 32;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_WRAP,              &no,                    sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &no,                    sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,                    sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,                    sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,                sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &hObject), "C_GenerateKey");
        printf("\n> AES key generated as handle    : %lu.\n", hObject);
}



// This function decrypts data
void decryptData(CK_ULONG encLen)
{
        CK_MECHANISM mech = {CKM_AES_ECB};
        CK_ULONG decLen = 0;
        checkOperation(p11Func->C_DecryptInit(hSession, &mech, hObject), "C_DecryptInit");
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, NULL_PTR, &decLen),"C_Decrypt");
	decryptedData = (CK_BYTE*)calloc(decLen, 1);
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, decryptedData, &decLen), "C_Decrypt");
	printf("\n> Encrypted data decrypted.\n");
}



// This function encrypts data
CK_ULONG encryptData()
{
        CK_MECHANISM mech = {CKM_AES_ECB};
        CK_ULONG encLen = 0;
        checkOperation(p11Func->C_EncryptInit(hSession, &mech, hObject),"C_EncryptInit");
        checkOperation(p11Func->C_Encrypt(hSession, plainText, strlen(plainText), NULL_PTR, &encLen),"C_Encrypt");
        encryptedData = (CK_BYTE*)calloc(encLen, 1);
        checkOperation(p11Func->C_Encrypt(hSession, plainText, strlen(plainText), encryptedData, &encLen),"C_Encrypt");
	printf("\n> Plaintext encrypted.\n");
        return encLen;
}



// This function displays data in bytes as HEX.
void bytesToHex(const CK_BYTE *data, CK_ULONG dataLen)
{
        for(int ctr=0;ctr<dataLen; ctr++)
        {
                printf("%02x",data[ctr]);
        }
        printf("\n");
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
	CK_ULONG encryptedDataLen = encryptData();
	decryptData(encryptedDataLen);

	printf("\n> Results - \n");
	printf("  --> Plaintext \t\t : %s\n", plainText);
	printf("  --> Plaintext (hex)\t\t : "); bytesToHex(plainText, strlen(plainText));
	printf("  --> Encrypted Data \t\t : "); bytesToHex(encryptedData, encryptedDataLen);
	printf("  --> Decrypted Data (hex) \t : "); bytesToHex(decryptedData, strlen(decryptedData));
	printf("  --> Decrypted text \t\t : %s", decryptedData);
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
