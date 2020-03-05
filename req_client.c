#include "proj.h"

static t_auth_code authCode;
static uint64_t label;
static uint64_t sessionKey;

void
ppc_init(CLIENT *clnt, char **argv, t_auth_code *authCode, RSA *clientKeypair,
				uint64_t *label, uint64_t *sessionKey) {
	t_string  *result_1;
	t_string  req_receipt_1_arg;
	char status[MAX_TINY_TOKEN];
	char serverSessionKeyTokenString[MAX_SMALL_TOKEN];
	char serverDecryptedAuthTokenString[MAX_SMALL_TOKEN];
	char clientPublicKeyFromServer[MAX_TOKEN];
	char clientPemPublicKeyString[MAX_TOKEN];
	char labelString[MAX_SMALL_TOKEN];
	char bolt11[MAX_LINE];
	char clearString[MAX_BUF];
	char encryptedString[MAX_BUF];
	char *base64EncodedEncryptedString;
	char clientReq[MAX_BUF];
	char encyptedRequest[MAX_BUF];
	char proofOfPayment[MAX_LINE];
	char token[MAX_TOKEN];
	char base64Signature[MAX_TOKEN];
	t_auth_code serverAuthToken;
	RSA *serverKey;
	size_t encLength;
	unsigned char *buf;
	FILE *file;
	char request[MAX_LINE];
	char out[MAX_TOKEN];
	char *clientRSAPublicKey;

	// allocate memory to hold client RSA public key
	clientRSAPublicKey = (char *) calloc(MAX_LINE, sizeof(char));
	if (clientRSAPublicKey == NULL) {
		printf("Out of memory...");
		exit (EXIT_FAILURE);
	}

	request[0] = '\0';
	strcpy(request, argv[2]);
	addToken(request, argv[3]);
	addToken(request, authCodeToString(authCode, out));
	rsaToPemPublicKeyString(clientKeypair, clientRSAPublicKey);
	addToken(request, clientRSAPublicKey);
	free(clientRSAPublicKey);

	printf("[1]::RPC: Client requesting server to provide invoice "
				"for PPC call: \n%s\n", request);

	// encrypt request to server using server's public key
	serverKey = RSA_new();
	if ((file = fopen(SERVER_PUB_KEY_FILENAME, "r")) == NULL) {
		printf("Must copy server's public key file to %s\n", 
				SERVER_PUB_KEY_FILENAME);
		// If server's public key file is missing on client machine:
		// client makes a request using a dummy public key for server 
		// to force server to generate a public key file, in case one 
		// does not already exist on server machine
		genRSAKeyPair(serverKey);
	}
	else {
		(void) fclose(file);
		pemPublicKeyinFileToRsa(serverKey, SERVER_PUB_KEY_FILENAME);
	}

	strcpy(clearString, getToken(request, TOKEN_ID_SERVICE_TYPE, token));
	addToken(clearString, getToken(request, TOKEN_ID_QUANTITY, token));
	addToken(clearString, getToken(request, TOKEN_ID_AUTH_CODE, token));
	if ((encLength = RSA_public_encrypt(strlen(clearString)+1, 
			(unsigned char*) clearString,
   			(unsigned char*) encryptedString, serverKey, 
			RSA_PKCS1_OAEP_PADDING)) == -1) {
		printf("Error encrypting message: FAILED!!!!\n");
		exit (EXIT_FAILURE);
	}

	// There are two tokens in encrypted message sent to server:
	//	1) base64 encoded encrypted bundle of:
        //         service_type+quantity+authCode
	//	2) client's RSA public key
	Base64Encode(encryptedString, encLength, 
				&base64EncodedEncryptedString);
	strcpy(clientReq, base64EncodedEncryptedString);
	addToken(clientReq, getToken(request, TOKEN_ID_PUBLIC_KEY, token));

	req_receipt_1_arg.data = clientReq;

	result_1 = req_receipt_1(&req_receipt_1_arg, clnt);
	if (result_1 == (t_string *) NULL) {
		clnt_perror (clnt, "call failed");
		exit (EXIT_FAILURE);
	}

	// Validate server's signature
	addToken(getToken(result_1->data, TOKEN_RETURN_ID_ENC_BUNDLE, 
				encryptedString), getToken(result_1->data, 
				TOKEN_RETURN_ID_ENC_PUBLIC_KEY, token));
	getToken(result_1->data, TOKEN_RETURN_ID_ENC_SIGNATURE, 
				base64Signature);
	if (verifySignature(serverKey, encryptedString, 
				strlen(encryptedString),
				base64Signature) == false) {
		printf("Server's signature did not verify!\n");
		exit (EXIT_FAILURE);
	}

	// Decrypt server's reply to initial client's message
	getToken(result_1->data, TOKEN_RETURN_ID_ENC_BUNDLE, token);
	Base64Decode(token, &buf, &encLength);
	if (RSA_private_decrypt(encLength, buf, clearString,
                       			clientKeypair, 
					RSA_PKCS1_OAEP_PADDING) == -1) {
  		printf("Error decrypting message: FAILED!!!\n");
		exit (EXIT_FAILURE);
	} else {
		addToken(clearString, getToken(result_1->data, 
					TOKEN_RETURN_ID_ENC_PUBLIC_KEY, 
					token));
	}

	if (!strcmp(getToken(clearString, 
			TOKEN_RETURN_ID_STATUS, status), 
			INVOICE_FAIL_CODE_INVALID_SERVICE_REQ)) {
		printf("Service not supported by server\n");
		exit (EXIT_FAILURE);
	}
	else if (strcmp(getToken(clearString, 
			TOKEN_RETURN_ID_STATUS, status), 
			INVOICE_SUCCESS_CODE)) {
		printf("Server failed to generate invoice\n");
		exit (EXIT_FAILURE);
	}
	else
	{
		printf("[5]::RPC: Client received bolt11_invoice "
				"from server\n");
		printf("Client received: %s\n", clearString);

		// check if received Session Key from the server
		if (getToken(clearString, TOKEN_RETURN_ID_SESSION_KEY, 
				serverSessionKeyTokenString) == NULL) {
			printf("Missing Session Key token from server\n");
			exit (EXIT_FAILURE);
		}
		*sessionKey = stringToSessionKey (
				serverSessionKeyTokenString);

		// get label identifying this transaction
		if (getToken(clearString, TOKEN_RETURN_ID_LABEL, 
						labelString) == NULL) {
			printf("Missing label from server\n");
			exit (EXIT_FAILURE);
		}
		*label = stringToLabel(labelString);

		// get bolt11
		if (getToken(clearString, TOKEN_RETURN_ID_BOLT11, 
						bolt11) == NULL) {
			printf("Missing bolt11 string from server\n");
			exit (EXIT_FAILURE);
		}

		// get client's public RSA key from server's reply
		if (getToken(clearString, TOKEN_RETURN_ID_KEY, 
						clientPublicKeyFromServer) == 
						NULL) {
			printf("Missing Client RSA public key "
						"from server\n");
			exit (EXIT_FAILURE);
		}

		// verify that this is the correct client public key		
		rsaToPemPublicKeyString(clientKeypair, 
						clientPemPublicKeyString);
		if (strcmp(clientPemPublicKeyString, 
						clientPublicKeyFromServer)) {
			printf("Server's returning a client public key "
						"that is invalid!\n");
			exit (EXIT_FAILURE);
		}

		// pay bolt11
		if (payInvoice(bolt11, proofOfPayment) == FAILED)
			exit (EXIT_FAILURE);
	}

	return;
}

char *
ppc_call(info_t *info, char *param) {
	t_string  *result_2;
	t_string  req_1_arg;
	char clearString[MAX_TOKEN];
	char labelString[MAX_SMALL_TOKEN];
	size_t encLength;
	char encryptedString[MAX_BUF];
	char *base64EncodedEncryptedString;

// authCode+label+param
	makeAuthorizationCode(info->authCode, info->sequenceNum);
	authCodeToString(info->authCode, clearString);
	addToken(clearString, labelToString(label, labelString));
	addToken(clearString, param);

	printf("\nMaking PPC Call to Server with the following "
			"parameters:\n%s\n", clearString);

	if ((encLength = RSA_public_encrypt(strlen(clearString)+1, 
			(unsigned char*) clearString,
   			(unsigned char*) encryptedString, info->serverKey, 
			RSA_PKCS1_OAEP_PADDING)) == -1) {
		printf("Error encrypting message: FAILED!!!!\n");
		exit (EXIT_FAILURE);
	}

	// There is one token in encrypted message sent to server:
	//	Base64 encoded encrypted bundle of:
        //      authCode+label+param
	Base64Encode(encryptedString, encLength, 
				&base64EncodedEncryptedString);
	
	req_1_arg.data = base64EncodedEncryptedString;  

	printf("[7]::RPC: Client requesting service from server\n");
	result_2 = req_1(&req_1_arg, info->clnt);
	if (result_2 == (t_string *) NULL) {
		clnt_perror (info->clnt, "Call failed");
	}
	else
	{
		printf("[12]::RPC: Client received result of query: %s\n", 
				result_2->data);
	}

	return "Done!";
}

void
ppc_build_info_block(CLIENT *clnt, t_auth_code *authCode, RSA *clientKeypair,
			uint64_t label, uint64_t sessionKey,
			RSA *serverKey, int32_t sequenceNum, info_t *info) {
	info->clnt = clnt;
	info->authCode = authCode;
	info->clientKeypair = clientKeypair;
	info->label = label;
	info->sessionKey = sessionKey;
	info->serverKey = serverKey;
	info->sequenceNum = sequenceNum;
	return;
} 

int
main (int argc, char *argv[])
{	
	CLIENT *clnt;
	int quantity = 0;
	RSA *clientKeypair;
	RSA *serverKey;
	uint32_t sequenceNum = 0;
	info_t info;
	char *ret;

	if (argc != 4) {
		printf ("usage: %s server_ip service_type quantity\n", 
					argv[0]);
		exit (EXIT_FAILURE);
	}

	// check to make sure quantity is valid
	if (!isQuantityValid(argv[3])) {
		printf("usage: invalid quantity specified: %s\n", 
					argv[3]);
		exit (EXIT_FAILURE);
	}

	printf("Client initialting Pay Per Call (PPC) request to %s "
					"for %d %s.\n",
		argv[1], atoi(argv[3]), argv[2]);

	clnt = clnt_create (argv[1], REQ_PROG, REQ_VERS, "tcp");
	if (clnt == NULL) {
		clnt_pcreateerror (argv[1]);
		exit (EXIT_FAILURE);
	}

	// Generate initial authorization code
	makeAuthorizationCode(&authCode, 0);

	// Generate client's RSA private/public key pair
	clientKeypair = RSA_new();
	genRSAKeyPair(clientKeypair);

	// Exchange secutity params between client & server and make payment
	ppc_init(clnt, argv, &authCode, clientKeypair, &label, &sessionKey);

	// Read in Server's public key from file
	serverKey = RSA_new();
	pemPublicKeyinFileToRsa(serverKey, SERVER_PUB_KEY_FILENAME);

	// Pause to give time for payment to be processed by lightning
	sleep(2); 

	// Make one or more service calls using ppc_call().
	// Before calling, ppc_call(), the client should call 
	// ppc_build_info_block() with correct sequence number.
	// Sequence numbers (sequenceNum) should be used in sequence from 1 
	// to "quantity" purchased for ppc_call(). The server keeps track of
	// the last sequenceNum received and uses that as the base for next
	// request.  Therefore, jumping over sequenceNum would result in 
	// invalidating (losing) the sequences that are jumped over (not used).
	// For example, if the client has ordered a 'quantity' of 4 of PPC 
	// calls, it can make up to 4 calls with sequenceNum = 1, 2, 3, 4.
	// If it makes its calls with sequenceNum = 1, 3, 4, it will lose
	// sequenceNum == 2 and cannot use it subsequently, since as soon
	// as server receives a request with sequenceNum = 3, it will advance
	// its base to sequenceNum = 3 and subsequently would expect the next
	// call to come in with sequenceNum = 4 and reject the call with
	// sequenceNum = 2.

	ppc_build_info_block(clnt, &authCode, clientKeypair, label,
				sessionKey, serverKey, (++sequenceNum), &info);
	ret = ppc_call(&info, "CSCO");

	ppc_build_info_block(clnt, &authCode, clientKeypair, label,
				sessionKey, serverKey, (++sequenceNum), &info);
	ret = ppc_call(&info, "JNPR");

	RSA_free(clientKeypair);
	RSA_free(serverKey);
	clnt_destroy (clnt);
	exit (EXIT_SUCCESS);
}
