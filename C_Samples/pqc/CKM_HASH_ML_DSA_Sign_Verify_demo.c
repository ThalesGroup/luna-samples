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
	- This sample demonstrates how to sign data and verify its signature using ML-DSA keys.
	- It utilises the CKM_HASH_ML_DSA mechanism to generate signature from an already hashed message.
	- For demonstration purpose, the sample generates an ML-DSA keypair as session objects.
	- CKM_HASH_ML_DSA is suitable only for single-part signing operations. It required CK_HASH_SIGN_ADDITIONAL_CONTEXT parameter.
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
CK_OBJECT_HANDLE objPubkey = 0; // Handle number of the public key.
CK_OBJECT_HANDLE objPrikey = 0; // Handle number of the private key.
CK_BYTE plainText[] = "Hello World, I've been waiting for the chance to see your face.";
CK_BYTE *messageDigest = NULL; // for storing the message digest.
CK_ULONG digestLen = 0;
CK_BYTE *signature = NULL; // used for storing the signature.
CK_ULONG signatureLen = 0; // length of the signature.
CK_HASH_SIGN_ADDITIONAL_CONTEXT additionalContext;



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
	free(messageDigest);
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



// Prints the syntax for executing this code.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password>\n\n", exeName);
}



// This function generates ML-DSA key pair.
void generateMLDSAKeyPair()
{
        CK_MECHANISM mech = {CKM_ML_DSA_KEY_PAIR_GEN};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_OBJECT_CLASS objClassPub = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS objClassPri = CKO_PRIVATE_KEY;
	CK_ML_DSA_PARAMETER_SET_TYPE paramType = CKP_ML_DSA_65;

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClassPub,   sizeof(CK_OBJECT_CLASS)},
                {CKA_PRIVATE,           &no,            sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &yes,           sizeof(CK_BBOOL)},
                {CKA_PARAMETER_SET,     &paramType,     sizeof(CK_ML_DSA_PARAMETER_SET_TYPE)}
        };
        CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClassPri,   sizeof(CK_OBJECT_CLASS)}
        };
        CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objPubkey, &objPrikey), "C_GenerateKeyPair");
        printf("\n> ML-DSA keypair generated.\n");
        printf("  --> Private key handle : %lu\n", objPrikey);
        printf("  --> Public key handle : %lu\n", objPubkey);
	printf("  --> ML-DSA Parameter : %lu\n", paramType);
}



// Computes SHA-256 Message Digest of the plaintext.
void computeHash()
{
	CK_MECHANISM mech = {CKM_SHA256};
	checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
	checkOperation(p11Func->C_Digest(hSession, plainText, sizeof(plainText)-1, NULL, &digestLen), "C_Digest");
	messageDigest = (CK_BYTE*)malloc(digestLen);
	checkOperation(p11Func->C_Digest(hSession, plainText, sizeof(plainText)-1, messageDigest, &digestLen), "C_Digest");
	printf("\n> Message digest computed.\n");
}



// Set values to additional context parameter structure.
void initParam()
{
	additionalContext.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
	additionalContext.pContext = NULL;
	additionalContext.ulContextLen = 0;
	additionalContext.hash = CKM_SHA256;
}



// Signs a plaintext using ML-DSA private key.
void signData()
{
	initParam();
	CK_MECHANISM mech = {CKM_HASH_ML_DSA, &additionalContext, sizeof(additionalContext)};
	checkOperation(p11Func->C_SignInit(hSession, &mech, objPrikey), "C_SignInit");
	checkOperation(p11Func->C_Sign(hSession, messageDigest, digestLen, NULL, &signatureLen), "C_Sign");
	signature = (CK_BYTE*)malloc(signatureLen);
	checkOperation(p11Func->C_Sign(hSession, messageDigest, digestLen, signature, &signatureLen), "C_Sign");
	printf("\n> Plaintext signed.\n");
	printf("  --> Signature Length : %ld.\n", signatureLen);
}



// Verifies signature
void verifyData()
{
	CK_MECHANISM mech = {CKM_HASH_ML_DSA, &additionalContext, sizeof(additionalContext)};
	checkOperation(p11Func->C_VerifyInit(hSession, &mech, objPubkey), "C_VerifyInit");
	checkOperation(p11Func->C_Verify(hSession, messageDigest, digestLen, signature, signatureLen), "C_Verify");
	printf("\n> Signature Verified.\n");
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
	generateMLDSAKeyPair();
	computeHash();
	signData();
	verifyData();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
