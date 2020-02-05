#include "proj.h"

static t_ctl_block *base_ptr = NULL;

t_ctl_block *
cache_add_blk() {
	t_ctl_block *ptr = (t_ctl_block *) calloc(1, sizeof(t_ctl_block));
	base_ptr = ptr;   // ###MKG remove later
	if (ptr == NULL) {
		printf("Out of memory...\n");
	}
	ptr->is_authorized = FALSE;
	ptr->state = STATE_IDLE;
	ptr->label = 0;
	strcpy(ptr->invoice, "");
	(ptr->authCode).noncePlusSequenceNumber = 0;
	(ptr->authCode).baseCode = 0;
	strcpy(ptr->serverPublicKey, "");
	strcpy(ptr->clientPublicKey, "");
	strcpy(ptr->statusAuthCodeServerPublicKeyBolt11, "");
	return ptr;
}

// ### Modify this code later
t_ctl_block *
find_block_from_label(char *label) {
	return base_ptr;
}
