#include <stdlib.h>
#include <jansson.h>
#include <time.h>
#include <math.h>
#include "req.h"
#include "proj.h"

static char empty = '\0';
static t_string emptyResult;

void
make_rand_label(t_ctl_block *blk) {
	srand(time(NULL));
	blk->label = rand();
	return;
}

float 
calc_fee(char *serviceType, int quantity) {
	float fee = FEE * (float) sqrt((double) quantity);
	return fee;       // simple fee formula for DEMO code
}

t_string *
req_receipt_1_svc(t_string *argp, struct svc_req *rqstp)
{
	static t_string result;
	t_ctl_block *blk;
	char quantity[MAX_TOKEN];
	char serviceType[MAX_LINE];
	char description[MAX_LINE] = {'\0'};
	float fee;

	fee = calc_fee(getToken(argp->data, 1, serviceType), 
		  atoi(getToken(argp->data, 2, quantity)));

	blk = cache_add_blk();
	if (blk == NULL) {
		emptyResult.data = &empty;
		return &emptyResult;
	}
	else {
		make_rand_label(blk);
		strcpy(description, getToken(argp->data, 1, serviceType));
		addToken(description, getToken(argp->data, 2, quantity));
		(blk->receiptResult).data = cl_make_invoice(blk, 
							    fee,
							    description);

		return &(blk->receiptResult);
	}
}

t_string *
req_1_svc(t_pair *argp, struct svc_req *rqstp)
{
	t_ctl_block *blk;
	static t_string  result;
	static char result_text[20] = "Result_String";

	printf("[8]::RPC: Server receives request for service\n");
        blk = find_block_from_auth_code("argp->authorization");  //###MKG take out the quotes
	cl_wait_for_payment(blk->label);  // ###MKG client must parse return from 1st RPC and pass it as authorization in 2nd RPC)

	result.data = result_text;
	printf("[11]::RPC: Server sent result of query: %s\n", result_text);

	return &result;
}
