#include <stdlib.h>
#include <jansson.h>
#include <time.h>
#include <math.h>
#include "req.h"
#include "proj.h"

static char empty[2];
static t_string emptyResult;

bool_t
is_service_type_valid(char *service_type) { 
	// List valid service types
	if (!strcmp(service_type, SERVICE_TYPE_1))  // stock quotes
		return TRUE;
	return FALSE;
}

// Use a simple fee structure for DEMO code
float 
calc_fee(char *serviceType, int quantity) {
	float fee = CALL_FEE * (float) sqrt((double) quantity);

	// No fee if service not supported
//	if (!is_service_type_valid(serviceType))
//		return NO_FEE;

	// Make sure a minimum fee is imposed, so lightning payment can find a route
	if (fee < MIN_BUNDLE_FEE)
		fee = MIN_BUNDLE_FEE;

	return fee;       
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

	blk = cache_add_blk();
	if (blk == NULL) {
		strcpy(empty, INVOICE_FAIL_CODE);
		emptyResult.data = empty; 
		return &emptyResult;
	}
	else {
		blk->label = make_rand_label();
		strcpy(description, getToken(argp->data, 
					TOKEN_ID_SERVICE_TYPE, serviceType));
		if (!is_service_type_valid(serviceType)) {
			strcpy(empty, INVOICE_FAIL_CODE_INVALID_SERVICE_REQ);
			emptyResult.data = empty; 
			return &emptyResult;			
		}
		addToken(description, getToken(argp->data, 
					TOKEN_ID_QUANTITY, quantity));
		getToken(argp->data, TOKEN_ID_PUBLIC_KEY, blk->clientPublicKey);
		fee = calc_fee(serviceType, atoi(quantity));
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
        blk = find_block_from_label("argp->authorization");  //###MKG pass label  as arg
	if (blk->state != STATE_PAYMENT_VERIFIED) {
		blk->state = STATE_WAIT_FOR_PAYMENT;
		if (cl_wait_for_payment(blk->label) == SUCCESS) {
			blk->state = STATE_PAYMENT_VERIFIED;
		}
		else {
			blk->state = STATE_PAYMENT_FAILED;
			strcpy(empty, INVOICE_FAIL_CODE);
			emptyResult.data = empty; 
			return &emptyResult;			
		}
	}

	result.data = result_text;
	printf("[11]::RPC: Server sent result of query: %s\n", result_text);

	return &result;
}
