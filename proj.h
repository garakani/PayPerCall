#include "req.h"

#define MAX_TOKEN 64
#define MAX_LINE 1024
#define MAX_BUF 4096
#define MAX_VALID_QUANTITY 1024*1024*1024
#define FEE (float) 1000           // milli Satoshi
#define INVOICE_SUCCESS_CODE    "0"
#define INVOICE_FAIL_CODE  "1"

struct t_ctl_block {
	int is_authorized;
	int label;
	char invoice[MAX_LINE];
	char authCode[MAX_TOKEN];
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
void cl_wait_for_payment(int);
t_ctl_block *find_block_from_auth_code(char *);
t_ctl_block *cache_add_blk();
int exec_command(char *, char *);

