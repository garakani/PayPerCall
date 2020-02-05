#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "proj.h"

uint64_t
make_rand_label() {
	static int firstTime = TRUE;
	int lower, upper;
	uint64_t r1, r2;

	if (firstTime) {
		srand(time(NULL));
		firstTime = FALSE;
	}
	lower = rand();
	srand((time_t) lower);
	upper = rand();

	r1 = ((uint64_t) upper) << 32;
	r2 = lower;
	return r1 | r2;
}

void
cl_authorize(t_ctl_block *blk) {
	uint64_t label = make_rand_label();
	uint64_t mask = INIT_AUTH_MASK;

	blk->is_authorized = TRUE;
	blk->state = STATE_IDLE;
	(blk->authCode).noncePlusSequenceNumber = label & 
						  mask;
	(blk->authCode).baseCode = make_rand_label();
	return;
}

void
cl_deauthorize(t_ctl_block *blk) {
	blk->is_authorized = FALSE;
	blk->state = STATE_IDLE;
	(blk->authCode).noncePlusSequenceNumber = 0;
	(blk->authCode).baseCode = 0;
	strcpy(blk->statusAuthCodeServerPublicKeyBolt11, "");
	// ###MKG put the block in the pool to be deallocated
}

bool_t
cl_is_authorized(t_ctl_block *blk) {
	return blk->is_authorized;
}

char *
cl_auth_code_to_string(t_auth_code *authCode, char *out) {
	int i;
	char s1[MAX_TOKEN], s2[MAX_TOKEN];

	if (sprintf(s1, "%lx", authCode->noncePlusSequenceNumber) > 0) {
		for (i = 0; i < ENCODED_STRING_SIZE-strlen(s1); i++) {
			out[i] = '0';
		}
		out[i] = '\0';
		strcat(out, s1);

		if (sprintf(s1, "%lx", authCode->baseCode) > 0) {
			for (i = 0; i < 16-strlen(s1); i++) {
				s2[i] = '0';
			}
			s2[i] = '\0';
			strcat(s2, s1);
			strcat(out, s2);
			return out;
		}
	}

	return NULL;
}

void
cl_string_to_auth_code(char *hexString, t_auth_code *authCode) {
	char s[MAX_LINE];
	strcpy(s, hexString);

	authCode->baseCode = strtol(s+16, NULL, 16);
	s[16]='\0';
	authCode->noncePlusSequenceNumber = strtol(s, NULL, 16);

	return;
}

// A validly formatted auth code from server must have 
// sequence number equal to zero, but randomized 
// value in nonce
bool_t
cl_is_server_auth_code_proper_format(t_auth_code *authCode) {
	return (authCode->noncePlusSequenceNumber &
		INIT_AUTH_PROPER_MASK_1) &&
		!(authCode->noncePlusSequenceNumber & 
		INIT_AUTH_PROPER_MASK_2); 
}

char *
cl_RSA_encrypt(char *in, char *out, char *pemKey) {
	strcpy(out, in);  // ###MKG fix this later
	return out;
}

char *
cl_RSA_decrypt(char *in, char *out, char *pemKey) {
	strcpy(out, in);  // ###MKG fix this later
	return out;
}

