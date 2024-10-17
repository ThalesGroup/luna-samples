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
	- This sample demonstrates how to use CKM_AES_KWP mechanism to wrap/unwrap a private key.
	- For this sample to work, your Luna HSM must be configured to allow Private Key Wrap, i.e Key Export Mode.
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

CK_OBJECT_HANDLE hPrivate = 0;
CK_OBJECT_HANDLE hPublic = 0;
CK_OBJECT_HANDLE hWrappingKey = 0;
CK_OBJECT_HANDLE hUnwrapped = 0;
CK_BYTE *wrappedKey = NULL;
CK_BYTE iv[] = {0x1, 0x2, 0x3, 0x3};


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



// This function generates RSA-2048 keypair
void generateKeyPair()
{
        CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
        CK_OBJECT_CLASS objPrivate = CKO_PRIVATE_KEY;
        CK_OBJECT_CLASS objPublic = CKO_PUBLIC_KEY;
        CK_ULONG mod = 2048;
        CK_BYTE exp[] = "10001";
        CK_ULONG yes = CK_TRUE;
        CK_ULONG no = CK_FALSE;

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &no,            sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &yes,           sizeof(CK_BBOOL)},
                {CKA_MODULUS_BITS,      &mod,           sizeof(CK_ULONG)},
                {CKA_PUBLIC_EXPONENT,   &exp,           sizeof(exp)-1},
                {CKA_CLASS,             &objPublic,     sizeof(CK_OBJECT_CLASS)}
        };
        CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objPrivate,    sizeof(CK_OBJECT_CLASS)}
        };
        CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate),"C_GenerateKeyPair");
	printf("\n> RSA-2048 keypair generated.\n");
	printf("  --> Private key handle : %lu.\n", hPrivate);
	printf("  --> Public key handle : %lu.\n", hPublic);
}



// This function generates an AES-256 key.
void generateWrappingKey()
{
        CK_MECHANISM mech = {CKM_AES_KEY_GEN};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ULONG keyLen = 32;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &no,            sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &no,            sizeof(CK_BBOOL)},
                {CKA_WRAP,              &yes,           sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &yes,           sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,        sizeof(CK_ULONG)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &hWrappingKey),"C_GenerateKey");
        printf("\n> AES-256 key generated for wrapping.\n");
	printf("  --> Wrapping key handle : %lu.\n", hWrappingKey);
}



// This function wraps the RSA private key using the generated AES-256 key.
CK_ULONG wrapPrivateKey()
{
        CK_ULONG encKeyLen = 0;
        CK_MECHANISM mech = {CKM_AES_KWP, iv, sizeof(iv)};
        checkOperation(p11Func->C_WrapKey(hSession, &mech, hWrappingKey, hPrivate, NULL_PTR, &encKeyLen),"C_WrapKey");
        wrappedKey = (CK_BYTE*)malloc(encKeyLen);
        checkOperation(p11Func->C_WrapKey(hSession, &mech, hWrappingKey, hPrivate, wrappedKey, &encKeyLen),"C_WrapKey");
        printf("\n> Private key wrapped.");
        return encKeyLen;
}



// This function unwraps the private key.
void unwrapPrivateKey(CK_ULONG dataLen)
{
        CK_MECHANISM mech = {CKM_AES_KWP, iv, sizeof(iv)};
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_OBJECT_CLASS objPrivate = CKO_PRIVATE_KEY;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,           sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objPrivate,    sizeof(CK_OBJECT_CLASS)},
                {CKA_KEY_TYPE,          &keyType,       sizeof(CK_KEY_TYPE)}
        };
        CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_UnwrapKey(hSession, &mech, hWrappingKey, wrappedKey, dataLen, attribPri, attribLenPri, &hUnwrapped),"C_UnWrapKey");
        printf("\n> Private key unwrapped as handle : %lu.\n", hUnwrapped);
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

	generateKeyPair();
	generateWrappingKey();
	CK_ULONG wrappedKeyLen = wrapPrivateKey();
	unwrapPrivateKey(wrappedKeyLen);

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
