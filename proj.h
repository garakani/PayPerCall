#include "req.h"

#define MAX_TOKEN 16
#define MAX_LINE 1024
#define MAX_BUF 4096
#define FEE 2000           // Same fee for all services (in milliSatoshi) for now

struct t_ctl_block {
	int is_authorized;
	int label;
	char authCode[MAX_TOKEN+1];
	char authCodeWithBolt11[MAX_LINE];
	t_string receiptResult;
	t_string result;
};
typedef struct t_ctl_block t_ctl_block;

/* prototypes for clightning API */
char *cl_make_invoice(t_ctl_block *, int, char *);
void cl_wait_for_payment(int);
t_ctl_block *find_block_from_auth_code(char *);
t_ctl_block *cache_add_blk();

