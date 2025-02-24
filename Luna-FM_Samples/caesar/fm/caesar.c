/*      **********************************************************************************
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

	Objective:
	- This code for Functionality Module reads a text sent from FM host and encrypts it using Caesar cipher technique.
	- The purpose of this code is to demonstrate how FM can be utilized to add a specific functionality, that isn't natively supported by an HSM.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cryptoki.h>
#include <fm.h>
#include "fm/common/fm_byteorder.h"
#include "caesar.h"
#include <fmsw.h>

static void dispatch_message(FmMsgHandle token, void* req, uint32_t req_len)
{
	uint32_t len; // Length of message.
	uint32_t slot; // embedded slot number
	uint32_t operation; // requested cryptographic operation.
	char buff[BUFFER_SIZE];
	char *rep;
	char ch;


	// Reads embedded slot number.
	if(req_len < sizeof(slot))
	{
		SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
		return;
	}
	slot = fm_betoh32(*(uint32_t *)req);
	req += sizeof(uint32_t);
	req_len -= sizeof(uint32_t);


	// Read requested cryptographic operation to perform. 1 for encrypt, 0 for decrypt.
	if(req_len < sizeof(operation))
	{
		SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
		return;
	}
	operation = fm_betoh32(*(uint32_t *)req);
	req += sizeof(uint32_t);
	req_len -= sizeof(uint32_t);


	// Read data size.
	if (req_len < sizeof(len))
	{
		SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
		return;
	}
	len = fm_betoh32(*(uint32_t *)req);
	req += sizeof(uint32_t);
	req_len -= sizeof(uint32_t);


	// Ensure sufficient memory is left.
	if ((len > sizeof(buff) || (req_len!=len)))
	{
		SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
		return;
	}


	// Copy message from the received request into buffer.
	memcpy(buff, req, len);


	// Encrypts message using Caesar shift technique.
	if(operation==1)
	{
		for(uint32_t ctr=0; ctr<len; ctr++)
		{
			ch = toupper(buff[ctr]);
			if (ch >= 65 && ch <= 90)
			{
				if (ch + 3 > 90)
					ch = ch - 23;
				else
					ch = ch + 3;
			}
			buff[ctr] = ch;

		}
	}
	else
	{
		for(uint32_t ctr=0; ctr<len; ctr++)
		{
			ch = toupper(buff[ctr]);
			if (ch >= 65 && ch <= 90)
			{
				if (ch - 3 < 65)
					ch+=23;
				else
					ch-=3;
			}
			buff[ctr] = ch;
		}
	}


	if ((rep = (char*)SVC_GetReplyBuffer(token, sizeof(len)+len)) == NULL)
	{
		SVC_SendReply(token, FM_ERR_OUT_OF_MEMORY);
		return;
	}
	*(uint32_t*)rep = fm_htobe32(len);
	rep+=sizeof(uint32_t);


	// Copy output into buffer
	memcpy(rep, buff, len);

	SVC_SendReply(token, FM_OK);
	return;
}


FM_RV Startup(void)
{
	printf("Caesar FM loaded.");
	return FMSW_RegisterRandomDispatch(GetFMID(), dispatch_message);
}
