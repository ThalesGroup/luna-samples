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




	OBJECTIVE : This sample shows how to derive a key using CKM_PKCS5_PBKD2 mechanism.
	- Please note that this mechanism is not FIPS Approved and will not work on Luna HSMs configured to operate in FIPS mode.
	- Executing this sample on a FIPS mode enabled Luna HSM would result in CKR_MECHANISM_INVALID.
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

CK_OBJECT_HANDLE hDerived = 0;
const CK_BYTE salt[] = "HelloHolaNamasteySalamKonichiwaNihao"; // Salt value to be used during key generation.
CK_PKCS5_PBKD2_PARAMS param;
const CK_BYTE password[] = "Th3W0rld$M0$+$3cur3P@$$w0rd";



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



// This function initializes the values for CK_PKCS5_PBKD2_PARAMS structure.
void initPBEParam()
{
        param.saltSource = CKZ_SALT_SPECIFIED;
        param.pSaltSourceData = (CK_VOID_PTR)salt; // Salt
        param.ulSaltSourceDataLen = sizeof(salt); // Salt len
        param.iterations = 1000; // iterations
        param.prf = CKP_PKCS5_PBKD2_HMAC_SHA1; // Pseudo Random Function to use.
        param.pPrfData = NULL; // should be null
        param.ulPrfDataLen = 0; // should be zero
        param.pPassword = (CK_UTF8CHAR_PTR)password; // password to be used
        param.ulPasswordLen = (CK_ULONG_PTR)sizeof(password); // password len;
}



// This function use CKM_PKCS5_PBKD2 to generate an AES-256 key from a specified password.
void generateSecretKey()
{
        initPBEParam(); // initialize CK_PKCS5_PBKD2_PARAMS object before using it.
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_KEY_TYPE keyType = CKK_AES; // Type of key to derive.
        CK_ULONG keyLen = 32; // length of the key to derive.
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;

        CK_MECHANISM mech = {CKM_PKCS5_PBKD2,&param,sizeof(param)};
        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_WRAP,              &no,            sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &no,            sizeof(CK_BBOOL)},
                {CKA_DERIVE,            &no,            sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,        sizeof(CK_ULONG)},
                {CKA_CLASS,             &objClass,      sizeof(CK_OBJECT_CLASS)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)}
        };

        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen,&hDerived),"C_GenerateKey");
	printf("\n> AES key derived.\n");
	printf("  --> Handle : %lu\n", hDerived);
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
	generateSecretKey();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
