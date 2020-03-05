#include "proj.h"

// Must make sure "s" has enough allocated space to concat the token
void
addToken(char *s, char *token) {
	if (s == NULL)
		exit (EXIT_FAILURE);
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
	if (s == NULL || strlen(s) == 0 || strlen(s) > (MAX_BUF-1))
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

int
execCommand(char *cmd_string, char *out) {
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
getInvoice(t_ctl_block *blk, int msatoshi, char *description) {
	char cmd_string[MAX_LINE];
	char *parsedInvoice;

	blk->invoice[0] = '\0';

	printf("[2]::RPC: Received client request to generate invoice\n");
	(void) sprintf(cmd_string, "lightning-cli invoice %d %ld %s", 
			msatoshi, blk->label, description); 
	printf("Generating invoice of %d msatoshi for label %ld for %s\n",
			msatoshi, blk->label, description);
	printf("[3]:Lightning_API: %s\n", cmd_string);

	if (execCommand(cmd_string, blk->invoice)) {
		printf("exec command failed to generate invoice\n");
		return INVOICE_FAIL_CODE;
	}

	return INVOICE_SUCCESS_CODE;
}

void
*waitForPayment(void *blk) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	uint64_t label = ((t_ctl_block *)blk)->label;
	out[0] = '\0';

	printf("\nCalling lightning API to wait for invoice payment for "
				"call ID %ld\n", label);
	(void) sprintf(cmd_string, "lightning-cli waitinvoice %ld", label);
	printf("Waiting on payment for label %ld\n", label);
	printf("\n[9]::Lightning_API: %s\n", cmd_string);

	if (execCommand(cmd_string, out)) {
		printf("could not verify payment on label %ld\n", label);
		((t_ctl_block *)blk)->state = STATE_PAYMENT_FAILED;
		return NULL;
	}

	printf("[10]::Lightning_NOTIFICATION: Payment for label %ld "
				"received\n", label);
	printf("%s\n", out);
	printf("Server done waiting for payment %ld\n", label);
	((t_ctl_block *)blk)->state = STATE_PAYMENT_VERIFIED;
	return NULL;
}

int payInvoice(char *bolt11, char *proofOfPayment) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';
	json_error_t error;
	json_t *hash = NULL;
	json_t *root;

	printf("Calling lightning API to pay invoice %s\n", bolt11);
	(void) sprintf(cmd_string, "lightning-cli pay %s", bolt11); 

	if (execCommand(cmd_string, proofOfPayment)) {
		printf("exec command failed to pay invoice\n");
		return FAILED;
	}

	root = json_loads(proofOfPayment, 0, &error);

        if (!root)
		printf("Error loading JSON invoice: %s\n", proofOfPayment);
	else
	        hash = json_object_get((json_t *) root, "payment_hash");

	json_decref(root);

	if (hash) {
		printf("\nPayment succeeded for blot11: %s\n", bolt11);
		printf("\nProof of payment:\n%s\n", proofOfPayment);
		return SUCCESS;
	}
	else {
		printf("\nPayment failed for blot11: %s\n", bolt11);
		printf("Failure info:\n%s\n", 
					proofOfPayment);
		return FAILED;
	}

}

