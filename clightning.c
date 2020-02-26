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

char *
cl_label_to_string(uint64_t label, char *out) {
	if (sprintf(out, "%ld", label) > 0)
		return out;
	else
		return NULL; 
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

int
cl_wait_for_payment(uint64_t label) {
	FILE *pipe;
	char out[MAX_BUF];
	char cmd_string[MAX_LINE];
	out[0] = '\0';

	printf("Calling lightning API to wait for invoice payment for "
				"call ID %ld\n", label);
	(void) sprintf(cmd_string, "lightning-cli waitinvoice %ld", label);
	printf("Waiting on payment for label %ld\n", label);
	printf("[9]::Lightning_API: %s\n", cmd_string);

	if (exec_command(cmd_string, out)) {
		printf("could not verify payment on label %ld\n", label);
		return FAILED;
	}

	printf("[10]::Lightning_NOTIFICATION: Payment for label %ld "
				"received\n", label);
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

	printf("Client paid invoice. Proof of payment:\n %s\n", 
					proofOfPayment);
	return SUCCESS;
}

