#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <jansson.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include "openssl_common.h"
#include "req.h"

#define SERVER_PUB_KEY_FILENAME "/home/mehryar/.ppc/server_pub.pem"
#define SERVER_KEY_PAIR_FILENAME "/home/mehryar/.ppc/key.pri"
#define MAX_TINY_TOKEN 16
#define MAX_SMALL_TOKEN 128
#define MAX_TOKEN 2560
#define MAX_LINE 3072
#define MAX_BUF 4096
#define MAX_VALID_QUANTITY 1024*1024*1024
#define CALL_FEE (float) 1000           // milli Satoshi
#define MIN_BUNDLE_FEE (float) 2000     // milli Satoshi
#define NO_FEE 0
#define SUCCESS 0
#define FAILED 1
#define INVOICE_SUCCESS_CODE "0"
#define INVOICE_FAIL_CODE  "1"
#define INVOICE_FAIL_CODE_ALLOC "2"
#define INVOICE_FAIL_CODE_DECRYPT  "3"
#define INVOICE_FAIL_CODE_INVALID_SERVICE_REQ "4"
#define INVOICE_FAIL_CODE_QUANTITY  "5"
#define INVOICE_FAIL_CODE_AUTH  "6"
#define TOKEN_ID_SERVICE_TYPE 1
#define TOKEN_ID_QUANTITY 2
#define TOKEN_ID_AUTH_CODE 3
#define TOKEN_ID_PUBLIC_KEY 4
#define TOKEN_ID_ENC_BUNDLE 1
#define TOKEN_ID_ENC_PUBLIC_KEY 2
#define TOKEN_RETURN_ID_STATUS 1
#define TOKEN_RETURN_ID_SESSION_KEY 2
#define TOKEN_RETURN_ID_LABEL 3
#define TOKEN_RETURN_ID_BOLT11 4
#define TOKEN_RETURN_ID_KEY 5
#define TOKEN_RETURN_ID_ENC_BUNDLE 1
#define TOKEN_RETURN_ID_ENC_PUBLIC_KEY 2
#define TOKEN_RETURN_ID_ENC_SIGNATURE 3
#define INIT_AUTH_MASK 0xFFFFFFFF00000000
#define INIT_AUTH_PROPER_MASK_1 0xFFFFFFFF00000000
#define INIT_AUTH_PROPER_MASK_2 0x00000000FFFFFFFF 
#define ENCODED_STRING_SIZE 16
#define STATE_IDLE 0
#define STATE_AUTHORIZED 1
#define STATE_WAIT_FOR_PAYMENT 2
#define STATE_PAYMENT_VERIFIED 3
#define STATE_PAYMENT_FAILED 4

// List valid service types below
#define SERVICE_TYPE_1 "quotes"

struct t_auth_code {
	uint64_t saltPlusSequenceNumber;
	uint64_t baseCode;
};
typedef struct t_auth_code t_auth_code;

struct t_ctl_block {
	int is_authorized;
	int state;
	char invoice[MAX_LINE];
	t_auth_code authCode;
	uint64_t sessionKey;
	uint64_t label;
	char clientPublicKey[MAX_LINE];
	char bolt11[MAX_LINE];
	char statusSessionKeyClientPublicKeyBolt11[MAX_BUF];
	t_string receiptResult;
	t_string result;
};
typedef struct t_ctl_block t_ctl_block;


/* prototypes */ 
void addToken(char *, char *);
char *getToken(char *, int, char *);
char *cl_make_invoice(t_ctl_block *, int, char *);
int cl_pay_invoice(char *, char *);
int cl_wait_for_payment(uint64_t);
t_ctl_block *find_block_from_label(char *);
t_ctl_block *cache_add_blk();
int exec_command(char *, char *);
uint64_t make_rand_label();
void cl_make_authorization_code(t_auth_code *);
void cl_authorize(t_ctl_block *);
void cl_deauthorize(t_ctl_block *);
bool_t cl_is_authorized(t_ctl_block *);
char *cl_auth_code_to_string(t_auth_code *, char *);
void cl_string_to_auth_code(char *, t_auth_code *);
bool_t cl_is_client_auth_code_proper_format(t_auth_code *);
char *cl_label_to_string(uint64_t, char *);
char *cl_session_key_to_string(uint64_t, char *);
uint64_t cl_string_to_session_key(char *);
uint64_t cl_string_to_label(char *);
char *cl_RSA_encrypt(char *in, char *out, char *pemPublicKey);
char *cl_RSA_decrypt(char *in, char *out, RSA *keypair);
void genRSAKeyPair(RSA *);
void rsaToPemPrivateKeyString(RSA *, char *);
void rsaToPemPublicKeyString(RSA *, char *);
void pemPublicKeyStringToRsa(RSA *, char *);
void pemPublicKeyinFileToRsa(RSA *, char *);
void rsaToPemPublicKeyInFile(RSA *, char *);
void Base64Encode( const unsigned char*, size_t, char**);
void Base64Decode(const char*, unsigned char**, size_t*);
char* RSASignBase64(RSA *, const unsigned char *, size_t);
_Bool verifySignature(RSA *, char *, size_t, char *);
void copyRSAKeypair(RSA *, RSA *); 
RSA *getRSAKey();
int isQuantityValid(char *);
