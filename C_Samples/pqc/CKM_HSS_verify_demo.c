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


	OBJECTIVE :
	- This sample demonstrates how to verify the digital signature of a data using CKM_HSS algorithm.
        - It uses an existing HSS public key to verify a signature.
        - The user must provide the data filename to be verified, along with the corresponding signature file, as input argument.
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

CK_BYTE *fileName = NULL; // Name of the file to read data from.
CK_BYTE *signatureFileName = NULL; // Name of the file containing signature.
long dataSize, signatureSize;

CK_OBJECT_HANDLE hPublic = 0; // Stores public key handle.
CK_BYTE *data = NULL; // Stores data to sign.
CK_BYTE *signature = NULL; // Stores the signature of signed data.




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
	free(fileName);
	free(signatureFileName);
	free(data);
	free(signature);
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



// Reads the data file to verify.
void readDataFile()
{
	FILE *fileRead;

	fileRead = fopen(fileName, "rb");

	if(!fileRead)
	{
		fprintf(stderr, "Failed to read %s.\n", fileName);
		exit(1);
	}

	printf("\n  --> Datafile : %s.\n", fileName);

	fseek(fileRead, 0, SEEK_END);
	dataSize = ftell(fileRead);
	rewind(fileRead);

	if(dataSize>32768)
	{
		fprintf(stderr, "This sample supports file of upto 32KB size.\n");
		fclose(fileRead);
		exit(1);
	}

	data = (CK_BYTE*)malloc(dataSize);
	fread(data, sizeof(CK_BYTE), dataSize, fileRead);
	fclose(fileRead);
}



// Reads the file containing the digital signature.
void readSignatureFile()
{
	FILE *sigRead;
	sigRead = fopen(signatureFileName, "rb");

	if(!sigRead)
	{
		fprintf(stderr, "Failed to read %s.\n", signatureFileName);
		exit(1);
	}

	printf("\n  --> Signature file : %s.\n", signatureFileName);

	fseek(sigRead, 0, SEEK_END);
	signatureSize = ftell(sigRead);
	rewind(sigRead);

	signature = (CK_BYTE*)malloc(signatureSize);
	fread(signature, sizeof(CK_BYTE), signatureSize, sigRead);
	fclose(sigRead);
}



// Loads the public keys for signature verification
void loadPublicKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_OBJECT_CLASS publicKey = CKO_PUBLIC_KEY;
	CK_KEY_TYPE hssKey = CKK_HSS;
	char keyLabel[32];
	CK_OBJECT_HANDLE objects[1];
	CK_ULONG objCount;

	printf("\n> Please input your HSS Public key Label : ");
	scanf("%31s", keyLabel);

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_TOKEN,		&yes,		sizeof(CK_BBOOL)},
		{CKA_CLASS,		&publicKey,	sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,		&hssKey,	sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,		&keyLabel,	strlen((const char*)keyLabel)}
	};

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, 4), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, objects, 1, &objCount), "C_FindObjects");
	if(objCount==0)
	{
		fprintf(stderr, "Public key %s not found.\n", keyLabel);
		hPublic = 0;
	}
	else
	{
		hPublic = objects[0];
	}
}



// Verify signature using CKM_HSS.
void verifyData()
{
	CK_MECHANISM mech = {CKM_HSS};
	checkOperation(p11Func->C_VerifyInit(hSession, &mech, hPublic), "C_VerifyInit");
	checkOperation(p11Func->C_Verify(hSession, data, dataSize, signature, signatureSize), "C_Verify");
	printf("\n> Signature verified.\n");
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password> <file_to_verify> <signature_file_name>\n\n", exeName);
}


int main(int argc, char **argv[])
{
	printf("\n%s\n", (char*)argv[0]);
	if(argc<5) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);
	slotPin = (CK_BYTE*)malloc(strlen((const char*)argv[2]));
	strncpy(slotPin, (const char*)argv[2], strlen((const char*)argv[2]));

	fileName = (CK_BYTE*)malloc(strlen((const char*)argv[3]));
	strncpy(fileName, (const char*)argv[3], strlen((const char*)argv[3]));

	signatureFileName = (CK_BYTE*)malloc(strlen((const char*)argv[4]));
	strncpy(signatureFileName, (const char*)argv[4], strlen((const char*)argv[4]));

	printf("\n> Reading files:\n");
	readDataFile();
	readSignatureFile();

	loadLunaLibrary();
	connectToLunaSlot();
	loadPublicKey();

	if(hPublic!=0)
	{
		verifyData();
	}

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
