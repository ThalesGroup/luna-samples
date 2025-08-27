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





        OBJECTIVE :
	- This sample demonstrates how to perform multi-threaded signing using a Luna HSM.
	- Cryptographic operations in a session are processed serially in Luna HSM, and each session can handle a limited number of operations.
	- To boost performance, a PKCS#11 application can open multiple threads, with a session open for each thread.
	- These sessions can then execute cryptographic operations in parallel, significantly improving performance.

*/





#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>


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

CK_OBJECT_HANDLE hPrivate = 0;
CK_OBJECT_HANDLE hPublic = 0;
CK_BYTE plainText[] = "Hello World, I've been waiting for the chance to see your face.";
int nThreads = 0;
int ops = 0;


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



//This function generates RSA-2048 keypair for C_Sign operation.
void generateRSAKeyPair()
{
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ULONG mod = 2048;
        CK_BYTE exp[] = "10001";

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &yes,           sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_MODULUS_BITS,      &mod,           sizeof(CK_ULONG)},
                {CKA_PUBLIC_EXPONENT,   &exp,           sizeof(exp)-1}
        };
        CK_ULONG pubTemplateLen = sizeof(attribPub)/sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,                   sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,                    sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,                    sizeof(CK_BBOOL)},
                {CKA_SENSITIVE, 	&yes,                   sizeof(CK_BBOOL)}
        };
        CK_ULONG priTemplateLen = sizeof(attribPri)/sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, pubTemplateLen, attribPri, priTemplateLen, &hPublic, &hPrivate), "C_GenerateKeyPair");
	printf(">\n RSA-2048 keypair generated.\n");
	printf("  --> Private key handle : %lu.\n", hPrivate);
	printf("  --> Public key handle : %lu.\n", hPublic);
}



// This function signs the plaintext.
void *signData(void *arg)
{
        CK_SESSION_HANDLE hChildSession = 0;
        CK_BYTE *signature = NULL;
        CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
        CK_ULONG sigLen = 0;

        checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hChildSession), "C_OpenSession");

	for(int ctr=0;ctr<ops;ctr++)
	{
        	checkOperation(p11Func->C_SignInit(hChildSession, &mech, hPrivate), "C_SignInit");
	        checkOperation(p11Func->C_Sign(hChildSession, plainText, sizeof(plainText)-1, NULL, &sigLen), "C_Sign");
        	signature = (CK_BYTE*)calloc(sigLen, 1);
	        checkOperation(p11Func->C_Sign(hChildSession, plainText, sizeof(plainText)-1, signature, &sigLen), "C_Sign");
		free(signature);
	}

       	checkOperation(p11Func->C_CloseSession(hChildSession), "C_CloseSession");
        return 0;
}



// Prints the syntax for executing this code.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	pthread_t *sign = NULL;

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

	printf("\n> Enter number of threads you want to start : ");
	scanf("%d",&nThreads);
	sign = (pthread_t*)malloc(nThreads * sizeof(pthread_t));
	printf("\n> Enter the number of sign operations each thread should perform : ");
	scanf("%d", &ops);

	printf("\n> Starting %d threads.\n", nThreads);
	for(int ctr=0;ctr<nThreads;ctr++)
	{
		pthread_create(&sign[ctr], NULL, &signData, NULL);
		printf("  --> Thread %d has started. TID : %lu.\n", ctr, sign[ctr]);
	}

	for(int ctr=0;ctr<nThreads;ctr++)
	{
		pthread_join(sign[ctr], NULL);
	}

	printf(">\nPlease wait ...\n");
	disconnectFromLunaSlot();
	free(sign);
	printf("\n> %d sign operation completed by %d threads.\n\n", (nThreads*ops), nThreads);
	freeMem();
	return 0;
}
