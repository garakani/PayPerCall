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
	ptr->label = 0;
	strcpy(ptr->invoice, "");
	strcpy(ptr->authCode, "");
	strcpy(ptr->serverPublicKey, "");
	strcpy(ptr->clientPublicKey, "");
	strcpy(ptr->statusAuthCodeServerPublicKeyBolt11, "");
	return ptr;
}

// ### Modify this code later
t_ctl_block *
find_block_from_auth_code(char *authCode) {
	return base_ptr;
}
