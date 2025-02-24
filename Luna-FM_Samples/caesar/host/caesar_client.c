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
	OBJECTIVE:
	- This code demonstrates how a host application communicates with an FM.
	- This code sends a text to the FM for encryption or decryption, and reads the received response.
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <md.h>
#include <mdStrings.h>
#include <fm/common/fm_byteorder.h>
#include <fm/common/fmerr.h>

MD_RV retValue = MDR_OK;
int slotId;
CK_SLOT_ID embeddedSlotId;
uint32_t adapterNumber;
uint32_t fmid;
char *message = NULL;
char *fmName = "Caesar";
char buffer[128];
uint32_t doEncryption = 0;


// Prints usage
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> -<OPERATION> <message>\n\n", exeName);
	printf("<OPERATIONS>:\n");
	printf("-E : Encrypt message\n");
	printf("-D : Decrypt message\n\n");
	printf("Example : \n");
	printf("./bin/caesar_client 0 -E \"Hello World.\"\n");
	printf("./bin/caesar_client 0 -D \"Khoor Zruog.\"\n\n");
}



// Checks the value returned by FM function.
void checkOperation(MD_RV retValue, const char *message)
{
	if(retValue!=MDR_OK)
	{
		printf("%s failed with : %s.\n", message, MD_RvAsString(retValue));
		MD_Finalize();
		exit(1);
	}
}



// Connects to FM.
void connectToFM()
{
	// Initializes Message Dispatch.
        checkOperation(MD_Initialize(), "MD_Initialize");

	// Get HSM index for slot.
	checkOperation(MD_GetHsmIndexForSlot(slotId, &adapterNumber), "MD_GetHsmIndexForSlot");

	//MD_GetHsmIndexForSlot(slotId
	checkOperation(MD_GetEmbeddedSlotID(slotId, &embeddedSlotId), "MD_GetEmbeddedSlotID");

	// Reads FM ID.
	checkOperation(MD_GetFmIdFromName(adapterNumber, fmName, (uint32_t)strlen(fmName), &fmid), "MD_GetFmIdFromName");
}



// Sends data to FM.
void sendRequest()
{
	MD_Buffer_t request[5]; // Buffer for sending requests to FM.
	MD_Buffer_t response[3];// Buffer for receiving response from FM.
	uint32_t slot, operation, message_len, temp, response_len, receive_len, fm_status;

	// Crafting the request buffer to be send to HSM. This buffer crafted to contains five segments.
	// 1. First segment contains the slot number.
	slot = fm_htobe32((uint32_t)embeddedSlotId);
	request[0].pData = (uint8_t *)&slot;
	request[0].length = 4;

	// 2. The second segment contains the flag for requested operation.
	operation = fm_htobe32((uint32_t)doEncryption);
	request[1].pData = (uint8_t *)&operation;
	request[1].length = 4;

	// 3. The third segment contains the length of our message.
	message_len = (uint32_t)strlen(message);
	temp = fm_htobe32(message_len);
	request[2].pData = (uint8_t *)&temp;
	request[2].length = 4;

	// 4. Fourth segment is the actual message.
	request[3].pData = (uint8_t *)message;
	request[3].length = message_len;

	// 5. We'll pass null as the fifth segment to indicate end of our request.
	request[4].pData = NULL;
	request[4].length = 0;


	// Crafting the buffer for storing a response from FM.
	response_len = 0;

	response[0].pData = (uint8_t *)&response_len;
	response[0].length = sizeof(response_len);

	response[1].pData = (uint8_t *)buffer;
	response[1].length = message_len;

	response[2].pData = NULL;
	response[2].length = 0;

	checkOperation(MD_SendReceive(adapterNumber, 0, (uint16_t)fmid, request, 10000, response, &receive_len, &fm_status), "MD_SendReceive");
	if(fm_status!=FM_OK)
	{
		printf("FM failed : %d", fm_status);
		MD_Finalize();
		exit(1);
	}
	else
	{
		response_len = fm_betoh32(*(uint32_t *)&response_len);
	}
}

int main(int argc, char *argv[])
{
	char *operation=NULL;
	if(argc<4)
	{
		usage((char*)argv[0]);
		exit(1);
	}
	// Read slot number from argument.
	slotId = atoi((const char*)argv[1]);

	// Read requested cryptographic operation. -E for Encrypt, -D for decrypt.
	operation = malloc(strlen((const char*)argv[2]));
	strncpy(operation, (char*)argv[2], 2);

	// Read the message passed as argument.
	message = malloc(strlen((const char*)argv[3]));
	strncpy(message, (char*)argv[3], strlen((const char*)argv[3]));

	if(strncmp(operation, "-E", 2)==0)
		doEncryption = 1;
	else if(strncmp(operation, "-D", 2)==0)
		doEncryption = 0;
	else
	{
		printf("%s is an invalid operation. Please use -E to encrypt, or -D to decrypt.\n", operation);
		exit(1);
	}
	connectToFM();
	printf("FM Name is : %s.\n", fmName);
	printf("FM ID is : %04x\n", fmid);
	printf("Adapter ID : %d\n", adapterNumber);
	printf("Embedded Slot ID : %ld.\n", embeddedSlotId);
	sendRequest();
	printf("Received message : %s.\n", buffer);

	// Finalize Message Dispatch.
	MD_Finalize();
	return 0;
}
