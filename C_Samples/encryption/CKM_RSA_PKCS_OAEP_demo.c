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



        OBJECTIVE : This sample demonstrates how to use CKM_RSA_PKCS_OAEP mechanism for encryption using Luna HSM.
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

CK_OBJECT_HANDLE hPrivate = 0; // Handle number of private key.
CK_OBJECT_HANDLE hPublic = 0; // Handle number of public key.
CK_RSA_PKCS_OAEP_PARAMS oaepParam; // OAEP parameters for encryption
CK_BYTE *encryptedData = NULL; // for storing encrypted data.
CK_BYTE *decryptedData = NULL; // for storing decrypted data.
const CK_BYTE rawData[] = "Earth is the third planet of our Solar System.";



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



// This function generates RSA-2048 bit key for encryption and decryption
void generateRSAKeyPair()
{
        CK_MECHANISM mech =  {CKM_RSA_PKCS_KEY_PAIR_GEN};
        CK_ULONG mod = 2048;
        CK_BYTE exp[] = "10001";
        CK_ULONG yes = CK_TRUE;
        CK_ULONG no = CK_FALSE;

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &no,            sizeof(CK_BBOOL)},
                {CKA_MODULUS_BITS,      &mod,           sizeof(CK_ULONG)},
                {CKA_PUBLIC_EXPONENT,   &exp,           sizeof(exp)-1},
        };
        CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SIGN,              &no,            sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)}
        };
        CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate),"C_GenerateKeyPair");
	printf("\n> RSA keypair generated : \n");
	printf("  --> Private key Handle : %lu\n", hPrivate);
	printf("  --> Public key Handle : %lu\n", hPublic);
}



// This function initializes the PSource for OAEP encryption.
void initOAEP()
{
	oaepParam.source = CKZ_DATA_SPECIFIED;
	oaepParam.pSourceData = (CK_VOID_PTR)"HelloWorld.";
	oaepParam.ulSourceDataLen = 11;
	oaepParam.hashAlg = CKM_SHA256;
	oaepParam.mgf = CKG_MGF1_SHA256;
	printf("\n> OAEP Param initialized.\n");
}



// This function encrypt data
CK_ULONG encryptData()
{
        initOAEP();
        CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &oaepParam, sizeof(oaepParam)};
        CK_ULONG encLen = 0;
        checkOperation(p11Func->C_EncryptInit(hSession, &mech, hPublic),"C_EncryptInit");
        checkOperation(p11Func->C_Encrypt(hSession, (CK_BYTE_PTR)rawData, strlen(rawData), NULL_PTR, &encLen),"C_Encrypt");
        encryptedData = (CK_BYTE*)calloc(encLen, sizeof(CK_BYTE));
        checkOperation(p11Func->C_Encrypt(hSession, (CK_BYTE_PTR)rawData, strlen(rawData), encryptedData, &encLen),"C_Encrypt");
	printf("\n> Plaintext encrypted.\n");
        return encLen;
}



// This function decrypts data
void decryptData(CK_ULONG dataLen)
{
        CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &oaepParam, sizeof(oaepParam)};
        CK_ULONG decLen = 0;
        checkOperation(p11Func->C_DecryptInit(hSession, &mech, hPrivate),"C_DecryptInit");
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, dataLen, NULL_PTR, &decLen),"C_Decrypt");
        decryptedData = (CK_BYTE*)calloc(decLen, sizeof(CK_BYTE));
        checkOperation(p11Func->C_Decrypt(hSession, encryptedData, dataLen, decryptedData, &decLen),"C_Decrypt");
	printf("\n> Encrypted data decrypted.\n");
}



// This function displays data in bytes as HEX
void bytesToHex(const CK_BYTE *data, CK_ULONG dataLen)
{
        for(int i = 0; i < dataLen; i++)
        {
                printf("%02x", data[i]);
        }
        printf("\n");
}



// Prints the syntax for executing this code.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_office_password>\n\n", exeName);
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
	generateRSAKeyPair();
	CK_ULONG dataLen = encryptData();
	decryptData(dataLen);
	disconnectFromLunaSlot();

	printf("\n> Results :- \n");
	printf("  --> Plain text : %s\n", rawData);
	printf("  --> Plain text as HEX : "); bytesToHex((CK_BYTE*)rawData, sizeof(rawData)-1);
        printf("  --> Encrypted Data : "); bytesToHex(encryptedData, dataLen);
	printf("  --> Decrypted Data : "); bytesToHex(decryptedData, sizeof(rawData)-1);

	freeMem();
	return 0;
}
