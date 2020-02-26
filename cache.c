#include "proj.h"

static t_ctl_block *base_ptr = NULL;

t_ctl_block *
cache_add_blk() {
	t_ctl_block *ptr = (t_ctl_block *) calloc(1, sizeof(t_ctl_block));
	base_ptr = ptr;   // ###MKG Remove Me !!!
	if (ptr == NULL) {
		printf("Out of memory...\n");
	}
	ptr->is_authorized = FALSE;
	ptr->state = STATE_IDLE;
	ptr->sessionKey = make_rand_label();
	ptr->label = 0;
	strcpy(ptr->invoice, "");
	(ptr->authCode).saltPlusSequenceNumber = 0;
	(ptr->authCode).baseCode = 0;
//	strcpy(ptr->serverPublicKey, "");
	strcpy(ptr->clientPublicKey, "");
	strcpy(ptr->statusSessionKeyClientPublicKeyBolt11, "");
	return ptr;
}

// ### Modify Me!!!
t_ctl_block *
find_block_from_label(char *label) {
	return base_ptr;
}
