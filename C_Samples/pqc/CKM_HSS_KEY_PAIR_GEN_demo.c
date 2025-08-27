        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                       	 *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2025 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************





        OBJECTIVE :
	- This sample demonstrates how to generate HSS key pair.
	- It required Luna HSM with firmware 7.8.9 or newer.
	- It also required Luna Client 10.8.0 or newer to be installed.
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

char *privKeyLabel = NULL; // Label for HSS private key.
char *pubKeyLabel = NULL; // Label for HSS public key.
int labelLen = 0; // Length of the label.
CK_ULONG hssLevel = 0; // Size of HSS tree.
CK_LMOTS_TYPE *lmotsType = NULL; // Type LMOTS to use in an HSS tree.
CK_LMS_TYPE *lmsType = NULL; // Type of LMS to use in an HSS tree.


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
	free(pubKeyLabel);
	free(lmotsType);
	free(lmsType);
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



// Asks for HSS keypair labels and formats the labels as <LABEL>-prvkey and <LABEL>-pubKey.
void inputKeyLabel()
{
	char keyLabel[64];
	printf("\n> Enter HSS Keypair label : ");
	scanf("%63s", keyLabel);
	labelLen = strlen(keyLabel) + 8;

	privKeyLabel = (char*)malloc(labelLen);
	snprintf(privKeyLabel, labelLen, "%s-prvkey", keyLabel);

	pubKeyLabel = (char*)malloc(labelLen);
	snprintf(pubKeyLabel, labelLen, "%s-pubkey", keyLabel);
}



// This function sets HSS level, LMS type and LMOTS to the HSS tree.
void setupHSSTree()
{
	int choice;
	printf("\n> Enter HSS Level (1-8) : ");
	scanf("%ld", &hssLevel);
	if(hssLevel < 1 || hssLevel > 8)
	{
		fprintf(stderr, "Invalid HSS Level");
		exit(1);
	}
	lmsType = (CK_LMS_TYPE*)malloc(hssLevel * sizeof(CK_LMS_TYPE));
	lmotsType = (CK_LMOTS_TYPE*)malloc(hssLevel * sizeof(CK_LMOTS_TYPE));

	for(int ctr=0; ctr<hssLevel; ctr++)
	{
		printf("\n --> Select LMS type to use for HSS-TREE %d of %ld\n", (ctr + 1), hssLevel);
		printf("\tLMS_SHA256_M32_H5 ....................... [1]\n");
		printf("\tLMS_SHA256_M32_H10 ...................... [2]\n");
		printf("\tLMS_SHA256_M32_H15 ...................... [3]\n");
		printf("\tLMS_SHA256_M32_H20 (Disabled)	\n"); // It was too slow, so I decided not to implement it.
		printf("\tLMS_SHA256_M32_H25 (Not Supported)\n"); // Not supported by Luna HSMs.
		printf("\tLMS_SHA256_M24_H5 ....................... [4]\n");
		printf("\tLMS_SHA256_M24_H10 ...................... [5]\n");
		printf("\tLMS_SHA256_M24_H15 ...................... [6]\n");
		printf("\tLMS_SHA256_M24_H20 (Disabled) \n"); // It was too slow, so I decided not to implement it.
		printf("\tLMS_SHA256_M24_H25 (Not Supported) \n"); // Not supported by Luna HSMs.
		printf("\tTYPE > : ");
		scanf("%d", &choice);

		switch(choice)
		{
			case 1: lmsType[ctr] = LMS_SHA256_M32_H5;
			break;
			case 2: lmsType[ctr] = LMS_SHA256_M32_H10;
			break;
			case 3: lmsType[ctr] = LMS_SHA256_M32_H15;
			break;
			case 4: lmsType[ctr] = LMS_SHA256_M24_H5;
			break;
                        case 5: lmsType[ctr] = LMS_SHA256_M24_H10;
                        break;
                        case 6: lmsType[ctr] = LMS_SHA256_M24_H15;
                        break;
			default: fprintf(stderr, "Invalid LMS type entered."); exit(1);
		}

		choice=0;
		printf("\n --> Select LMOTS type to use for HSS-TREE %d of %ld\n", (ctr + 1), hssLevel);
		printf("\tLMOTS_SHA256_N32_W1   [1]\n");
		printf("\tLMOTS_SHA256_N32_W2   [2]\n");
		printf("\tLMOTS_SHA256_N32_W4   [3]\n");
		printf("\tLMOTS_SHA256_N32_W8   [4]\n");
		printf("\tLMOTS_SHA256_N24_W1   [5]\n");
		printf("\tLMOTS_SHA256_N24_W2   [6]\n");
		printf("\tLMOTS_SHA256_N24_W4   [7]\n");
		printf("\tLMOTS_SHA256_N24_W8   [8]\n");
		printf("\tTYPE > : ");
		scanf("%d", &choice);

		switch(choice)
		{
			case 1: lmotsType[ctr] = LMOTS_SHA256_N32_W1;
			break;
			case 2: lmotsType[ctr] = LMOTS_SHA256_N32_W2;
			break;
			case 3: lmotsType[ctr] = LMOTS_SHA256_N32_W4;
			break;
			case 4: lmotsType[ctr] = LMOTS_SHA256_N32_W8;
			break;
			case 5: lmotsType[ctr] = LMOTS_SHA256_N24_W1;
			break;
                        case 6: lmotsType[ctr] = LMOTS_SHA256_N24_W2;
                        break;
                        case 7: lmotsType[ctr] = LMOTS_SHA256_N24_W4;
                        break;
                        case 8: lmotsType[ctr] = LMOTS_SHA256_N24_W8;
                        break;
			default: fprintf(stderr, "Invalid LMOTS type entered."); exit(1);
		}
	}
}


// Generates HSS keypair.
void generateHSSKeyPair()
{
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	CK_OBJECT_HANDLE hPrivateKey;
	CK_OBJECT_HANDLE hPublicKey;
        CK_MECHANISM mech = {CKM_HSS_KEY_PAIR_GEN};

	CK_ATTRIBUTE privateKeyAttributes[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,		&no,			sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,		&no,			sizeof(CK_BBOOL)},
		{CKA_DECRYPT,			&no,			sizeof(CK_BBOOL)},
		{CKA_SIGN,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&no,			sizeof(CK_BBOOL)},
		{CKA_UNWRAP,			&no,			sizeof(CK_BBOOL)},
		{CKA_HSS_LEVELS,		&hssLevel,		sizeof(CK_ULONG)},
		{CKA_HSS_LMS_TYPES,		lmsType,		sizeof(CK_LMS_TYPE) * hssLevel},
		{CKA_HSS_LMOTS_TYPES,		lmotsType,		sizeof(CK_LMOTS_TYPE) * hssLevel},
		{CKA_LABEL,			privKeyLabel,		labelLen-1}
	};
	CK_ULONG privAttrLen = sizeof(privateKeyAttributes) / sizeof(*privateKeyAttributes);

	CK_ATTRIBUTE publicKeyAttributes[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,		&no,			sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,			&no,			sizeof(CK_BBOOL)},
		{CKA_VERIFY,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&no,			sizeof(CK_BBOOL)},
		{CKA_LABEL,			pubKeyLabel,		labelLen-1}
	};
	CK_ULONG pubAttrLen = sizeof(publicKeyAttributes) / sizeof(*publicKeyAttributes);

	checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, publicKeyAttributes, pubAttrLen, privateKeyAttributes, privAttrLen, &hPrivateKey, &hPublicKey), "C_GenerateKeyPair");
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
	inputKeyLabel();
	setupHSSTree();
	generateHSSKeyPair();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
