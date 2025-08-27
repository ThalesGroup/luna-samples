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





        OBJECTIVE : This sample demonstrates how to make a copy of an object.
	- C_CopyObjects also allows modifying certain attributes from the source object to the target object.
	- When run, this sample generates an AES key and then makes a copy of it with different attribute values.
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

CK_OBJECT_HANDLE sourceObject = 0;
CK_OBJECT_HANDLE targetObject = 0;



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



// This function generates a 256 bit AES key.
void generateAESKey()
{
        CK_MECHANISM mech = {CKM_AES_KEY_GEN};
        CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_TRUE;
        CK_ULONG keyLen = 32;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_WRAP,              &yes,                    sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &yes,                    sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,                   sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &yes,                   sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &yes,                   sizeof(CK_BBOOL)},
                {CKA_VALUE_LEN,         &keyLen,                sizeof(CK_ULONG)},
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
        checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &sourceObject),"C_GenerateKey");
        printf("\n> AES Key generated with handle : %lu\n", sourceObject);
}



// Displays Boolean values as either YES or NO.
const char* printBool(CK_BBOOL yesno)
{
        if(yesno==CK_TRUE)
                return "YES";
        else
                return "NO";
}



// This function displays the attributes set to the key.
void showAttributes(CK_ULONG hObject)
{
        CK_BBOOL a_token;
        CK_BBOOL a_private;
        CK_BBOOL a_encrypt;
        CK_BBOOL a_decrypt;
        CK_BBOOL a_wrap;
        CK_BBOOL a_unwrap;
        CK_BBOOL a_modifiable;
        CK_BBOOL a_extractable;
        CK_BBOOL a_sensitive;

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &a_token,               sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &a_private,             sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &a_encrypt,             sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &a_decrypt,             sizeof(CK_BBOOL)},
                {CKA_WRAP,              &a_wrap,                sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &a_unwrap,              sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &a_modifiable,          sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &a_extractable,         sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &a_sensitive,           sizeof(CK_BBOOL)}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_GetAttributeValue(hSession, hObject, attrib, attribLen),"C_GetAttributeValue");

        printf("\nObject Handle                  : %lu.", hObject);
        printf("\nTOKEN OBJECT                   : %s.", printBool(a_token));
        printf("\nPRIVATE OBJECT                 : %s.", printBool(a_private));
        printf("\nENCRYPTION ALLOWED             : %s.", printBool(a_encrypt));
        printf("\nDECRYPTION ALLOWED             : %s.", printBool(a_decrypt));
        printf("\nCAN WRAP                       : %s.", printBool(a_wrap));
        printf("\nCAN UNWRAP                     : %s.", printBool(a_unwrap));
        printf("\nEXTRACTABLE                    : %s.", printBool(a_extractable));
        printf("\nMODIFIABLE                     : %s.", printBool(a_modifiable));
        printf("\nSENSITIVE                      : %s.\n", printBool(a_sensitive));
}



// This function makes a copy of the generated object with different attributes.
void makeCopy()
{
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;

	CK_ATTRIBUTE attrib[] = 
	{
                {CKA_TOKEN,             &no,                    sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &yes,                   sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &no, 	                sizeof(CK_BBOOL)},
                {CKA_WRAP,              &yes,                   sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &no,                    sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,                   sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,                    sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,                    sizeof(CK_BBOOL)},
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
	checkOperation(p11Func->C_CopyObject(hSession, sourceObject, attrib, attribLen, &targetObject), "C_CopyObject");
	printf("\n> AES key copied.\n");
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
	printf("\n> Attributes of the generated key.\n");
	showAttributes(sourceObject);
	makeCopy();
	printf("\n> Attributes of copied key.\n");
	showAttributes(targetObject);

	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
