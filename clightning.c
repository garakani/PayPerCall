#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include "req.h"
#include "proj.h"

void
cl_authorize(t_ctl_block *blk) {  // ###MKG write this generate plain(8) + random (16) cypher
	blk->is_authorized = TRUE;
	strcpy(blk->authCode, "000000000000000000000000");
}

void
cl_deauthorize(t_ctl_block *blk) {
	blk->is_authorized = FALSE;
	strcpy(blk->authCode, "");
	strcpy(blk->statusAuthCodeServerPublicKeyBolt11, "");
	// ###MKG put the block in the pool to be deallocated
}

bool_t
cl_is_authorized(t_ctl_block *blk) {
	return blk->is_authorized;
}

void
addToken(char *s, char *token) {
	if (s == NULL)
		exit(1);
	strcat(s, ":");
	strcat(s, token);
	return;
}

char *
getToken(char *s, int index, char *token) {
	int i, length, first, last, numTokens = 1, nextToken = 1;


	// invalid input string
	if (s == NULL || strlen(s) == 0 || strlen(s) > (MAX_LINE-1))
		return NULL;

	strcpy(token, s);

	// count and chop tokens
	length = strlen(s);
	for (i=0; i < length; i++) {
		if (token[i] == ':') {
			numTokens++;
			token[i] = '\0';
		}
	}

	// invalid index
	if (index < 1 || index > numTokens)
		return NULL;

	else if (index == 1)
		return token;

	// find and return token
	else {
		for (i=0; i < length; i++) {
			if (token[i] == '\0') {
				nextToken++;
				if (nextToken == index) {
					return token+i+1;
				}
			}
		}
	}

	return NULL;
}

char *
cl_parse_invoice(t_ctl_block *blk) {
	json_error_t error;
	json_t *bolt11;
	json_t *root = json_loads(blk->invoice, 0, &error);
	char b11[MAX_LINE];
	char line[MAX_LINE];

	*b11 = '\0';
        if (!root) {
		printf("Error loading JSON invoice: %s\n", blk->invoice);
		cl_deauthorize(blk);
	}
	else {
	        bolt11 = json_object_get((json_t *) root, "bolt11");
		if (bolt11 == NULL) {
			cl_deauthorize(blk);
		}
		else {
			strcat(b11, json_string_value(bolt11));
		}
	}

	json_decref(root);

	// Construct return parameters for client
	if (cl_is_authorized(blk)) {
		strcpy(blk->statusAuthCodeServerPublicKeyBolt11, INVOICE_SUCCESS_CODE);
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, blk->authCode);
                if (exec_command("cat ~/.ppc/id_ppc.pub" , blk->serverPublicKey)
				|| strlen(blk->serverPublicKey) == 0) {
			printf("Could not find the server public key (PEM file): ~/PPC/id_ppc.pub\n");
			printf("----- returning fail code to client\n");
			return INVOICE_FAIL_CODE;
		}
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, blk->serverPublicKey);
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, b11);
        	printf("[4]::RPC: Sending bolt11_invoice to client for label %d\n", 
				blk->label);
		printf("%s\n", blk->statusAuthCodeServerPublicKeyBolt11);
		return blk->statusAuthCodeServerPublicKeyBolt11;
	}
	else
		return INVOICE_FAIL_CODE;
}

int
exec_command(char *cmd_string, char *out) {
	FILE *pipe;
	pipe = popen(cmd_string, "r");
	if (pipe != NULL) {
		while (1) {
			char *line;
      			char buf[MAX_LINE];
      			line = fgets(buf, sizeof buf, pipe);
      			if (line == NULL)
				break;
			else if ((strlen(line) + strlen(out)) < MAX_BUF)
				strcat(out, line);
		}
    		pclose(pipe);
		return 0;
	}
	else
		return 1;
}

char *
cl_make_invoice(t_ctl_block *blk, int msatoshi, char *description) {
	char cmd_string[MAX_LINE];

	blk->invoice[0] = '\0';

	printf("[2]::RPC: Received client request to generate invoice\n");
	(void) sprintf(cmd_string, "lightning-cli invoice %d %d %s", 
			msatoshi, blk->label, description); 
	printf("Generating invoice of %d msatoshi for label %d for %s\n",
			msatoshi, blk->label, description);
	printf("[3]:Lightning_API: %s\n", cmd_string);

	if (exec_command(cmd_string, blk->invoice))
		return INVOICE_FAIL_CODE;

	printf("Full invoice is %s\n", blk->invoice);

	cl_authorize(blk);

	return cl_parse_invoice(blk);  // ###MKG client must dealh with "" retval
}

void
cl_wait_for_payment(int label) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';

	printf("Calling lightning API to wait for invoice payment for call ID %d\n", label);
	(void) sprintf(cmd_string, "lightning-cli waitinvoice %d", label); 
	printf("Waiting on payment for call ID %d\n", label);
	printf("[9]::Lightning_API: %s\n", cmd_string);
        sleep(3);
//	pipe = popen("lightning-cli waitinvoice [label]", "r");
	pipe = popen("", "r");
	if (pipe != NULL) {
		while (1) {
			char *line;
      			char buf[MAX_LINE];
      			line = fgets(buf, sizeof buf, pipe);
      			if (line == NULL)
				break;
			else if ((strlen(line) + strlen(out)) < MAX_BUF)
				strcat(out, line);
		}
    		pclose(pipe);
	}
	else
		printf("cl_wait_for_payment(): Pipe failed to open\n");

	printf("[10]::Lightning_NOTIFICATION: Payment for call ID %d received\n", label);
	printf("Server done waiting for payment for call ID %d\n", label);
	return;
}

void cl_pay_invoice(char *bolt11) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';

	printf("Calling lightning API to pay invoice %s\n", bolt11);
	(void) sprintf(cmd_string, "lightning-cli pay %s", bolt11); 
	printf("[6]::Lightning_API: %s\n", cmd_string);
        sleep(3);
//	pipe = popen("lightning-cli pay <bolt11>", "r");
	pipe = popen("", "r");
	if (pipe != NULL) {
		while (1) {
			char *line;
      			char buf[MAX_LINE];
      			line = fgets(buf, sizeof buf, pipe);
      			if (line == NULL)
				break;
			else if ((strlen(line) + strlen(out)) < MAX_BUF)
				strcat(out, line);
		}
    		pclose(pipe);
	}
	else
		printf("cl_wait_for_payment(): Pipe failed to open\n");

	printf("Client paid invoice %s\n", bolt11);
	return;
}

