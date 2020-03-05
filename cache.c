#include "proj.h"

static struct t_link_list_element *linkListBase[1024*64];

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

t_ctl_block *
cacheAddBlk(uint64_t label) {

	pthread_mutex_lock(&mutex);

	unsigned short hashKey;
	t_ctl_block *ptr = (t_ctl_block *) calloc(1, sizeof(t_ctl_block));

	if (ptr == NULL) {
		printf("Out of memory...\n");
		exit (1);
	}

	hashKey = label ^ (label >> 16) ^ (label >> 32) ^ 
					(label >> 48);

	struct t_link_list_element *e = (struct t_link_list_element *) 
				calloc(1, sizeof(struct t_link_list_element));
	if (e == NULL) {
		printf("Out of memory...\n");
		exit (1);
	}
	else {
		e->element = ptr;
		e->label = label;

		if (linkListBase[hashKey] != NULL) {
			e->next = linkListBase[hashKey];
		}
		linkListBase[hashKey] = e;
	}

	ptr->isAuthorized = FALSE;
	ptr->state = STATE_IDLE;
	ptr->sessionKey = makeRandLabel();
	ptr->label = 0;
	ptr->minSeqAllowed = 0;
	ptr->maxSeqAllowed = 0;
	strcpy(ptr->invoice, "");
	(ptr->authCode).saltPlusSequenceNumber = 0;
	(ptr->authCode).baseCode = 0;
	strcpy(ptr->clientPublicKey, "");
	strcpy(ptr->statusSessionKeyClientPublicKeyBolt11, "");

	pthread_mutex_unlock(&mutex);

	return ptr;
}

t_ctl_block *
findBlockFromLabel(char *labelString) {

	pthread_mutex_lock(&mutex);

	t_ctl_block *retValue;

	uint64_t label = stringToLabel(labelString);
	unsigned short hashKey = label ^ (label >> 16) ^ (label >> 32) ^ 
					(label >> 48);
	struct t_link_list_element *next = linkListBase[hashKey];

	while (next != NULL) {
		if (next->label == label)
			break;
		next = next->next;
	}

	if (next == NULL)
		retValue = NULL;
	else
		retValue = next->element;

	pthread_mutex_unlock(&mutex);

	return retValue;

}
