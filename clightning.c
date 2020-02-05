#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include "req.h"
#include "proj.h"

// Must make sure "s" has enough allocated space to concat the token
void
addToken(char *s, char *token) {
	if (s == NULL)
		exit(1);
	if (token == NULL)   // nothing to do
		return;
	strcat(s, ":");
	strcat(s, token);
	return;
}

char *
getToken(char *s, int index, char *token) {
	int i, length, first, last, numTokens = 1, nextToken = 1;
	char buf[MAX_BUF];

	// invalid input string
	if (s == NULL || strlen(s) == 0 || strlen(s) > (MAX_LINE-1))
		return NULL;

	strcpy(buf, s);

	// count and chop tokens
	length = strlen(s);
	for (i=0; i < length; i++) {
		if (buf[i] == ':') {
			numTokens++;
			buf[i] = '\0';
		}
	}

	// invalid index
	if (index < 1 || index > numTokens)
		return NULL;

	else if (index == 1) {
		strcpy(token, buf);
		return token;
	}

	// find and return token
	else {
		for (i=0; i < length; i++) {
			if (buf[i] == '\0') {
				nextToken++;
				if (nextToken == index) {
					strcpy(token, buf+i+1);
					return token;
				}
			}
		}
	}

	return NULL;
}

char *
cl_label_to_string(uint64_t label, char *out) {
	if (sprintf(out, "%ld", label) > 0)
		return out;
	else
		return NULL; 
}

char *
cl_parse_invoice(t_ctl_block *blk) {
	json_error_t error;
	json_t *bolt11;
	json_t *root = json_loads(blk->invoice, 0, &error);
	char b11[MAX_LINE];
	char line[MAX_LINE];
	char serverPrivateKey[MAX_LINE];
	char encryptedAuth[MAX_TOKEN];
	char hexString[MAX_TOKEN];

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
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, 
				cl_auth_code_to_string(&(blk->authCode), 
				cl_RSA_encrypt(hexString, encryptedAuth,
				blk->clientPublicKey)));
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, 
				cl_label_to_string(blk->label, hexString));
                if (exec_command("cat ~/.ppc/id_ppc.pub" , blk->serverPublicKey) ||
				strlen(blk->serverPublicKey) == 0) {
			printf("Could not find the server public key: ~/PPC/id_ppc.pub\n");
			printf("Could not parse invoice. Returning fail code to client\n");
			return INVOICE_FAIL_CODE;
		}
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, blk->serverPublicKey);
		addToken(blk->statusAuthCodeServerPublicKeyBolt11, b11);
        	printf("[4]::RPC: Sending bolt11_invoice to client for label %ld\n", 
				blk->label);
		printf("%s\n", blk->statusAuthCodeServerPublicKeyBolt11);
		return blk->statusAuthCodeServerPublicKeyBolt11;
	}
	else {
		printf("Could not parse invoice. Returning fail code to client\n");
		return INVOICE_FAIL_CODE;
	}
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
	char *parsedInvoice;

	blk->invoice[0] = '\0';

	printf("[2]::RPC: Received client request to generate invoice\n");
	(void) sprintf(cmd_string, "lightning-cli invoice %d %ld %s", 
			msatoshi, blk->label, description); 
	printf("Generating invoice of %d msatoshi for label %ld for %s\n",
			msatoshi, blk->label, description);
	printf("[3]:Lightning_API: %s\n", cmd_string);

	if (exec_command(cmd_string, blk->invoice)) {
		printf("exec command failed to generate invoice\n");
		return INVOICE_FAIL_CODE;
	}

	printf("Full invoice is %s\n", blk->invoice);

	cl_authorize(blk);

	parsedInvoice = cl_parse_invoice(blk);

	return parsedInvoice;
}

int
cl_wait_for_payment(uint64_t label) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';

	printf("Calling lightning API to wait for invoice payment for call ID %ld\n", label);
	(void) sprintf(cmd_string, "lightning-cli waitinvoice %ld", label); 
	printf("Waiting on payment for label %ld\n", label);
	printf("[9]::Lightning_API: %s\n", cmd_string);

	if (exec_command(cmd_string, out)) {
		printf("could not verify payment on label %ld\n", label);
		return FAILED;
	}

	printf("[10]::Lightning_NOTIFICATION: Payment for label %ld received\n", label);
	printf("%s\n", out);
	printf("Server done waiting for payment %ld\n", label);
	return SUCCESS;
}

int cl_pay_invoice(char *bolt11, char *proofOfPayment) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';

	printf("Calling lightning API to pay invoice %s\n", bolt11);
	(void) sprintf(cmd_string, "lightning-cli pay %s", bolt11); 
	printf("[6]::Lightning_API: %s\n", cmd_string);

	if (exec_command(cmd_string, proofOfPayment)) {
		printf("exec command failed to pay invoice\n");
		return FAILED;
	}

	printf("Client paid invoice. Proof of payment:\n %s\n", proofOfPayment);
	return SUCCESS;
}

