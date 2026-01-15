        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2026 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************


        OBJECTIVE :
	- This samples demonstrates how to use SFNTExtension function to establish connection to a RemotePED server.
	- It executes C_Login after successfully establishing the RemotePED connection.
	- It then generates an ephemeral RSA key pair, performs signing, logs out, and disconnects from the RemotePED.
	- SFNTExtensions are supported only by Luna HSMs. This sample works with a PED based Luna PCIe HSM, or Luna USB HSM.
	- Please setup a remote-ped ID using pedClient utility as follows:

		Step 1) Start PedClient
			> pedClient -m start

		Step 2) Set RemotePED ID
			> pedClient -m setid -id rped-id -id_ip rped-server-ip -id_port rped-server-port
			  Example:
				> pedClient -m setid -id 1234 -id_ip 10.164.50.100 -id_port 1503

		Step 3) Assign RemotePED ID to an HSM serial.
			> pedClient -m assignid -id rped-id -id_serialnumber hsm-serial
			  Example:
				> pedClient -m assignid -id 1234 -id_serialnumber 763298

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


CK_FUNCTION_LIST *p11Func = NULL; // Stores all pkcs11 functions.
CK_SFNT_CA_FUNCTION_LIST *sfntFunc = NULL; // Stores all sfnt functions.

CK_SLOT_ID slotId = 0; // slot id
CK_ULONG pedId = 0; // Ped-ID to use for RemotePED connection.
CK_SESSION_HANDLE hSession = 0; // for session handle.
CK_BYTE *slotPin = NULL; // crypto officer password.
CK_BYTE rawData[] = "Earth is the third planet of our Solar System.";
CK_BYTE *signature = NULL; // for storing signature.
CK_OBJECT_HANDLE hPrivate = 0; // Stores private key handle.
CK_OBJECT_HANDLE hPublic = 0; // Stores public key handle.


void freeMem();

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

	// Loads PKCS#11 functions.
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

	// Loads SFNTExtensions.
	#ifdef OS_UNIX
            CA_GetFunctionList = (CK_CA_GetFunctionList)dlsym(libHandle, "CA_GetFunctionList"); // Loads symbols on Unix/Linux
        #else
            CA_GetFunctionList = (CK_CA_GetFunctionList)GetProcAddress(libHandle, "CA_GetFunctionList"); // Loads symbols on Windows.
        #endif

	CA_GetFunctionList(&sfntFunc);
	if(sfntFunc==NULL)
	{
		printf("Failed to load SFNT functions.\n");
		exit(1);
	}
	printf("\n> SafeNet Extensions loaded.\n");
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


// Checks for RPV before connecting to the RemotePED Server.
void checkRPVStatus()
{
	CK_ULONG status = 0;
	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	checkOperation(sfntFunc->CA_GetRemotePEDVectorStatus(slotId, &status), "CA_GetRemotePEDVectorStatus");
	if(status==0)
	{
		printf("RPV is not initialized for this slot.\n\n");
		p11Func->C_Finalize(NULL_PTR);
		freeMem();
		exit(1);
	}
	printf("\n> RPV is initialized for this slot.\n");
}


// Initiates a RemotePED connection.
void connectToRemotePED()
{
	CK_BBOOL no = CK_FALSE;
	checkOperation(sfntFunc->CA_ConnectRemotePED(slotId, pedId, no, NULL_PTR), "CA_ConnectRemotePED");
	printf("\n> Connected to the RemotePED server.\n");
	checkOperation(sfntFunc->CA_SetPedId(slotId, pedId), "CA_SetPedId");
}


// Closes the RemotePED connection.
void disconnectFromRemotePED()
{
	checkOperation(sfntFunc->CA_DisconnectRemotePED(slotId, pedId), "CA_DisconnectRemotePED");
	printf("\n> Connection to the RemotePED server closed.\n");
}


// Connects to a Luna slot (C_OpenSession, C_Login)
void connectToLunaSlot()
{
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



// Generates RSA-2048 keypair for signing data
void generateRsaKeyPair()
{
	CK_MECHANISM mech = {CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN};
	CK_ULONG modulus = 2048;
	CK_BYTE publicExpo[] = "10001"; 
	CK_OBJECT_CLASS objPrivate = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS objPublic = CKO_PUBLIC_KEY;
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;

	CK_ATTRIBUTE attribPrivate[] =  
	{
		{CKA_CLASS,		&objPrivate, 	sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN,		&no,		sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,		&yes,		sizeof(CK_BBOOL)},
		{CKA_PRIVATE,		&yes,		sizeof(CK_BBOOL)},
		{CKA_DERIVE,		&no,		sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, 	&no,		sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,	&no,		sizeof(CK_BBOOL)},
		{CKA_SIGN,		&yes,		sizeof(CK_BBOOL)},
		{CKA_DECRYPT,		&yes,		sizeof(CK_BBOOL)},
	};
	CK_ULONG attribLenPri = sizeof(attribPrivate)/sizeof(*attribPrivate);

	CK_ATTRIBUTE attribPublic[] = 
	{
		{CKA_CLASS,		&objPublic,	sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN,		&no,		sizeof(CK_BBOOL)},
		{CKA_PRIVATE,		&yes,		sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,		&yes,		sizeof(CK_BBOOL)},
		{CKA_VERIFY,		&yes,		sizeof(CK_BBOOL)},
		{CKA_MODULUS_BITS,	&modulus,	sizeof(CK_ULONG)},
		{CKA_PUBLIC_EXPONENT,	&publicExpo,	sizeof(publicExpo)-1}
	};

	CK_ULONG attribLenPub = sizeof(attribPublic)/sizeof(*attribPublic);

	checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPublic, attribLenPub, attribPrivate, attribLenPri, &hPublic, &hPrivate),"C_GenerateKeyPair");

	printf("\n> RSA key generate.\n");
	printf("  --> Private key handle : %ld\n",hPrivate);
	printf("  --> Public key handle : %ld\n",hPublic);
}



// Sign data using sha256WithRSA.
void signData()
{
	CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
	CK_ULONG signatureLen = 0;
	checkOperation(p11Func->C_SignInit(hSession, &mech, hPrivate), "C_SignInit");
	checkOperation(p11Func->C_Sign(hSession, rawData, sizeof(rawData)-1, NULL, &signatureLen), "C_Sign");
	signature = (CK_BYTE*)calloc(signatureLen, 1);
	checkOperation(p11Func->C_Sign(hSession, rawData, sizeof(rawData)-1, signature, &signatureLen), "C_Sign");
	printf("\n> Raw Data signed.\n");
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
	free(signature);
}



// Prints usage.
void usage(const char exeName[30])
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <ped_id> <crypto_officer_password>\n\n", exeName);
}



int main(int argc, char **argv[])
{
	printf("\n%s\n", (char*)argv[0]);
	if(argc<4) {
		usage((char*)argv[0]);
		exit(1);
	}
	slotId = atoi((const char*)argv[1]);
	pedId = atoi((const char*)argv[2]);

	size_t len = strlen((const char*)argv[3]);
	slotPin = (CK_BYTE*)malloc(len);
	strncpy(slotPin, (const char*)argv[3], len);

	loadLunaLibrary();
	checkRPVStatus();
	connectToRemotePED();
	connectToLunaSlot();
	generateRsaKeyPair();
	signData();
	disconnectFromRemotePED();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
