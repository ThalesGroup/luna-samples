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



	OBJECTIVE : This sample demonstrates how to use C_GetAttributeValue function to read attributes of an object.
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

CK_OBJECT_HANDLE objHandle = 0;



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


// This function searches for an object with the specified label.
void searchObject()
{
	CK_ULONG objCount = 0;
	CK_OBJECT_HANDLE found[1];
	CK_BBOOL yes = CK_TRUE;
	CK_BYTE label[20];

	printf("\nEnter the label of object to search : ");
	fgets(label, 20, stdin);

	CK_ATTRIBUTE attrib[] = 
	{
		{CKA_TOKEN, 	&yes, 	sizeof(CK_BBOOL)},
		{CKA_LABEL, 	&label,  strlen(label)-1}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectInit");
	checkOperation(p11Func->C_FindObjects(hSession, found, 1, &objCount), "C_FindObject");
	if(objCount == 0)
	{
		printf("\n> No object found with label %s", label);
		disconnectFromLunaSlot();
		freeMem();
		exit(1);
	}
	objHandle = found[0];
}



// Displays Boolean values as either YES or NO.
const char* printBool(CK_BBOOL yesno)
{
        if(yesno==CK_TRUE)
                return "YES";
        else
                return "NO";
}



// This function will read the attribute of an Object and display it.
void showAttributes()
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
        CK_BYTE label[20];

        CK_ATTRIBUTE attrib[] =
        {
                {CKA_TOKEN,             &a_token,       	sizeof(CK_BBOOL)},
                {CKA_PRIVATE,           &a_private,     	sizeof(CK_BBOOL)},
                {CKA_ENCRYPT,           &a_encrypt,     	sizeof(CK_BBOOL)},
                {CKA_DECRYPT,           &a_decrypt,     	sizeof(CK_BBOOL)},
                {CKA_WRAP,              &a_wrap,        	sizeof(CK_BBOOL)},
                {CKA_UNWRAP,            &a_unwrap,      	sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &a_modifiable,  	sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &a_extractable, 	sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &a_sensitive,   	sizeof(CK_BBOOL)},
                {CKA_LABEL,             &label,         	sizeof(label)-1}
        };
        CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

        checkOperation(p11Func->C_GetAttributeValue(hSession, objHandle, attrib, attribLen),"C_GetAttributeValue");

        printf("\nObject Handle                  : %lu.", objHandle);
        printf("\nKey Label                      : %s", label);
        printf("TOKEN OBJECT                   : %s.", printBool(a_token));
        printf("\nPRIVATE OBJECT                 : %s.", printBool(a_private));
        printf("\nENCRYPTION ALLOWED             : %s.", printBool(a_encrypt));
       	printf("\nDECRYPTION ALLOWED             : %s.", printBool(a_decrypt));
        printf("\nCAN WRAP                       : %s.", printBool(a_wrap));
        printf("\nCAN UNWRAP                     : %s.", printBool(a_unwrap));
        printf("\nEXTRACTABLE                    : %s.", printBool(a_extractable));
        printf("\nMODIFIABLE                     : %s.", printBool(a_modifiable));
        printf("\nSENSITIVE                      : %s.\n", printBool(a_sensitive));
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
	searchObject();
	showAttributes();
	disconnectFromLunaSlot();
	freeMem();
	return 0;
}
