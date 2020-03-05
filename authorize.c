#include "proj.h"

// generate a uint64 pseudo-random number using the 32 bit rand()
uint64_t
makeRandLabel() {
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

// Make a new authorization code
void
makeAuthorizationCode(t_auth_code *authCode, int sequenceNum) {
	uint64_t salt;
	uint64_t mask = INIT_AUTH_MASK;

	// Always generate new salt
	salt = makeRandLabel();

	// Initial authorization code: generate baseCode
	if (sequenceNum == 0) {

		authCode->baseCode = makeRandLabel();
	}
	
	authCode->saltPlusSequenceNumber = (salt & mask) | 
					(uint64_t) sequenceNum;

	return;
}

void
authorize(t_ctl_block *blk) {
	uint64_t label = makeRandLabel();
	uint64_t mask = INIT_AUTH_MASK;
	blk->isAuthorized = TRUE;
	blk->state = STATE_AUTHORIZED;
	return;
}

void
deauthorize(t_ctl_block *blk) {
	blk->isAuthorized = FALSE;
	blk->state = STATE_IDLE;
	(blk->authCode).saltPlusSequenceNumber = 0;
	(blk->authCode).baseCode = 0;
	strcpy(blk->statusSessionKeyClientPublicKeyBolt11, "");
}

bool_t
isAuthorized(t_ctl_block *blk) {
	return blk->isAuthorized;
}

char *
authCodeToString(t_auth_code *authCode, char *out) {
	int i;
	char s1[MAX_TOKEN], s2[MAX_TOKEN];

	if (sprintf(s1, "%lx", authCode->saltPlusSequenceNumber) > 0) {
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
stringToAuthCode(char *hexString, t_auth_code *authCode) {
	char s[MAX_LINE];
	strcpy(s, hexString);

	authCode->baseCode = strtol(s+16, NULL, 16);
	s[16]='\0';
	authCode->saltPlusSequenceNumber = strtol(s, NULL, 16);

	return;
}

char *
sessionKeyToString(uint64_t sessionKey, char *out) {
	sprintf(out, "%lx", sessionKey);
	return out;
}

uint64_t
stringToSessionKey(char *hexString) {
	uint64_t sessionKey;
	sessionKey = strtol(hexString, NULL, 16);
	return sessionKey;
}

uint64_t
stringToLabel(char *hexString) {
	uint64_t label;
	label = strtol(hexString, NULL, 10);
	return label;
}


char *
labelToString(uint64_t label, char *out) {
	if (sprintf(out, "%ld", label) > 0)
		return out;
	else
		return NULL; 
}

// A validly formatted auth code from client must have 
// sequence number initially equal to zero, but randomized 
// value in salt
bool_t
isClientAuthCodeProperFormat(t_auth_code *authCode) {
	return (authCode->saltPlusSequenceNumber &
		INIT_AUTH_PROPER_MASK_1) &&
		!(authCode->saltPlusSequenceNumber & 
		INIT_AUTH_PROPER_MASK_2); 
}


