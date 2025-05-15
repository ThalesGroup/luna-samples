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
	- This sample demonstrates how to sign data using CKM_HSS algorithm.
        - It uses an existing HSS private key to perform signing operation.
        - Data to be signed is read from a file.
	- The resulting signature is written to a new file with the same name, appended with .sig extension.
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
long fileSize;
CK_OBJECT_HANDLE hPrivate = 0; // Stores private key handle.
CK_BYTE *data = NULL; // Stores data to sign.
CK_BYTE *signature = NULL; // Stores the signature of signed data.
CK_ULONG signatureLen = 0;


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
	free(data);
	free(signature);
}



// Checks if a P11 operation was a success or failure
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		if(rv==0x203)
			printf("\n%s failed with CKR_KEY_EXHAUSTED.\n\n", message);
		else
			printf("\n%s failed with Ox%lX\n\n",message,rv);

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



// Reads the file to sign.
void readFile()
{
	FILE *fileRead;

	fileRead = fopen(fileName, "rb");

	if(!fileRead)
	{
		fprintf(stderr, "Failed to read %s.\n", fileName);
		exit(1);
	}

	printf("\n> Reading file : %s.\n", fileName);

	fseek(fileRead, 0, SEEK_END);
	fileSize = ftell(fileRead);
	rewind(fileRead);

	if(fileSize>32768)
	{
		fprintf(stderr, "This sample supports file of upto 32KB size.\n");
		fclose(fileRead);
		exit(1);
	}

	data = (CK_BYTE*)malloc(fileSize);
	fread(data, sizeof(CK_BYTE), fileSize, fileRead);
	fclose(fileRead);
}



// Loads the signing keys.
void loadSigningKey()
{
	CK_BBOOL yes = CK_TRUE;
	CK_OBJECT_CLASS privateKey = CKO_PRIVATE_KEY;
	CK_KEY_TYPE hssKey = CKK_HSS;
	char keyLabel[32];
	CK_OBJECT_HANDLE objects[1];
	CK_ULONG objCount;

	printf("\n> Please input your HSS Private key Label : ");
	scanf("%31s", keyLabel);

	CK_ATTRIBUTE attrib[] = 
	{
		{CKA_TOKEN,		&yes,		sizeof(CK_BBOOL)},
		{CKA_CLASS,		&privateKey,	sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,		&hssKey,	sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,		&keyLabel,	strlen((const char*)keyLabel)}
	};

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, 4), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, objects, 1, &objCount), "C_FindObjects");
	if(objCount==0)
	{
		fprintf(stderr, "Signing key %s not found.\n", keyLabel);
		hPrivate = 0;
	}
	else
	{
		hPrivate = objects[0];
	}
}



// Outputs CKA-ID and the remaining number of One Time Signatures.
void showKeyInfo()
{
	CK_BYTE ckaid[16];
	CK_ULONG hssKeysRemaining;

	CK_ATTRIBUTE attrib[] =
	{
		{CKA_ID,			&ckaid,			sizeof(ckaid)},
		{CKA_HSS_KEYS_REMAINING,	&hssKeysRemaining,	sizeof(CK_ULONG)}
	};

	checkOperation(p11Func->C_GetAttributeValue(hSession, hPrivate, attrib, 2), "C_GetAttributeValue");

	printf("  --> HSS KEYS REMAINING : %ld.\n", hssKeysRemaining);
	printf("  --> CKA ID : ");

        for(int ctr=0; ctr<16; ctr++)
        {
                printf("%02x",ckaid[ctr]);
        }
	printf("\n");

}



// Sign data using CKM_HSS.
void signData()
{
	CK_MECHANISM mech = {CKM_HSS};
	checkOperation(p11Func->C_SignInit(hSession, &mech, hPrivate), "C_SignInit");
	checkOperation(p11Func->C_Sign(hSession, data, fileSize, NULL, &signatureLen), "C_Sign");
	signature = (CK_BYTE*)calloc(signatureLen, 1);
	checkOperation(p11Func->C_Sign(hSession, data, fileSize, signature, &signatureLen), "C_Sign");
	printf("\n> File signed.\n");
}



// Writes signature to a file.
void writeSignature()
{
	FILE *sigWrite;
	char *signatureFileName = NULL;
	size_t fileNameLen = strlen(fileName);
	size_t extLen = 4;

	signatureFileName = (char*)malloc(fileNameLen + 3);
	strncpy(signatureFileName, fileName, fileNameLen);
	strncat(signatureFileName, ".sig", extLen);
	printf("\n> Signature written to file : %s.\n", signatureFileName);

	sigWrite = fopen(signatureFileName, "wb");
	fwrite(signature, sizeof(CK_BYTE), signatureLen, sigWrite);
	fclose(sigWrite);
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_office_password> <file_to_sign>\n\n", exeName);
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
	strncpy(slotPin, (const char*)argv[2], strlen((const char*)argv[2]));

	fileName = (CK_BYTE*)malloc(strlen((const char*)argv[3]));
	strncpy(fileName, (const char*)argv[3], strlen((const char*)argv[3]));

	readFile();
	loadLunaLibrary();
	connectToLunaSlot();
	loadSigningKey();
	showKeyInfo();

	if(hPrivate!=0)
	{
		signData();
		writeSignature();
	}

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
