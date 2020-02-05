#include "req.h"

#define MAX_TOKEN 64
#define MAX_LINE 1024
#define MAX_BUF 4096
#define MAX_VALID_QUANTITY 1024*1024*1024
#define FEE (float) 1000           // milli Satoshi
#define INVOICE_SUCCESS_CODE "0"
#define INVOICE_FAIL_CODE  "1"
#define INVOICE_FAIL_CODE_INVALID_SERVICE_REQ  "2"
#define TOKEN_ID_SERVICE_TYPE 1
#define TOKEN_ID_QUANTITY 2
#define TOKEN_ID_PUBLIC_KEY 3
#define TOKEN_RETURN_ID_STATUS 1
#define TOKEN_RETURN_ID_AUTH 2
#define TOKEN_RETURN_ID_LABEL 3
#define TOKEN_RETURN_ID_KEY 4
#define TOKEN_RETURN_ID_BOLT11 5
#define INIT_AUTH_MASK 0xFFFFFFFF00000000
#define INIT_AUTH_PROPER_MASK_1 0xFFFFFFFF00000000
#define INIT_AUTH_PROPER_MASK_2 0x00000000FFFFFFFF 
#define ENCODED_STRING_SIZE 16

// List valid service types below
#define SERVICE_TYPE_1 "quotes"

struct t_auth_code {
	uint64_t noncePlusSequenceNumber;
	uint64_t baseCode;
};
typedef struct t_auth_code t_auth_code;

struct t_ctl_block {
	int is_authorized;
	char invoice[MAX_LINE];
//	char authCode[MAX_TOKEN];
	t_auth_code authCode;
	uint64_t label;
	char serverPublicKey[MAX_LINE];
	char clientPublicKey[MAX_LINE];
	char statusAuthCodeServerPublicKeyBolt11[MAX_LINE];
	t_string receiptResult;
	t_string result;
};
typedef struct t_ctl_block t_ctl_block;


/* prototypes */ 
void addToken(char *, char *);
char *getToken(char *, int, char *);
int isQuantityValid(char *);
char *cl_make_invoice(t_ctl_block *, int, char *);
void cl_wait_for_payment(uint64_t);
t_ctl_block *find_block_from_label(char *);
t_ctl_block *cache_add_blk();
int exec_command(char *, char *);
uint64_t make_rand_label();
void cl_authorize(t_ctl_block *);
void cl_deauthorize(t_ctl_block *);
bool_t cl_is_authorized(t_ctl_block *);
char *cl_auth_code_to_string(t_auth_code *, char *);
void cl_string_to_auth_code(char *, t_auth_code *);
bool_t cl_is_server_auth_code_proper_format(t_auth_code *);
char *cl_label_to_string(uint64_t, char *);
char *cl_RSA_encrypt(char *in, char *out, char *pemPublicKey);
char *cl_RSA_decrypt(char *in, char *out, char *pemPrivateKey);



