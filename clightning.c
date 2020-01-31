#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include "req.h"
#include "proj.h"

void
cl_authorize(t_ctl_block *blk) {  // ###MKG write this
}

void
cl_deauthorize(t_ctl_block *blk) {
	blk->is_authorized = FALSE;
	strcpy(blk->authCode, "");
	strcpy(blk->authCodeWithBolt11, "");
}

bool_t
cl_is_authorized(t_ctl_block *blk) {
	return blk->is_authorized;
}

char *
cl_parse_invoice(t_ctl_block *blk, char *out) {
	json_error_t error;
	json_t *bolt11;
	json_t *root = json_loads(out, 0, &error);
	char b11[MAX_LINE];

	*b11 = '\0';
        if (!root) {
		printf("Error loading JSON invoice: %s\n", out);
		cl_deauthorize(blk);
	}
	else {
	        bolt11 = json_object_get((json_t *) root, "bolt11");
		if (bolt11 == NULL) {
			cl_deauthorize(blk);
		}
		else {
			strcat(b11, json_string_value(bolt11));
			printf("bolt11 is: %s\n", b11);
		}
	}

	// Generate expanded bolt11 that includes authorization code preamble
	if (cl_is_authorized(blk)) {
		strcpy(blk->authCodeWithBolt11, blk->authCode);
		strcat(blk->authCodeWithBolt11, b11);
	}

	free(out);	//###MKG fix this
	json_decref(root);

        printf("[4]::RPC: Sending bolt11_invoice to client for call ID %d\n", blk->label);
	return blk->authCodeWithBolt11;
}

char *
cl_make_invoice(t_ctl_block *blk, int msatoshi, char *description) {
	FILE *pipe;

	char cmd_string[MAX_LINE];

	char *out = (char *) calloc(MAX_BUF, sizeof(char));
	if (out == NULL) {
		printf("Out of memory...\n");
		exit(1);
	}
	out[0] = '\0';

	printf("[2]::RPC: Received client request to generate invoice\n");
	(void) sprintf(cmd_string, "lightning-cli invoice %d %d %s", 
			msatoshi, blk->label, description); 
	printf("Generating invoice of %d msatoshi for call ID %d for %s\n",
			msatoshi, blk->label, description);
	printf("[3]:Lightning_API: %s\n", cmd_string);
	pipe = popen(cmd_string, "r");
	if (pipe != NULL) {    // ###MKG clean this up. put in new subroutine
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
		printf("cl_make_invoice(): Pipe failed to open\n");

	printf("Full invoice is %s\n", out);

	cl_authorize(blk);

	return cl_parse_invoice(blk, out);  // ###MKG client must dealh with "" retval
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

