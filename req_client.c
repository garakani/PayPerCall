#include "proj.h"

static t_auth_code authCode;
static uint64_t sessionKey;
static uint64_t label;

void
ppc_request(char *host, char *request, RSA *clientKeypair) {
	CLIENT *clnt;
	t_string  *result_1;
	t_string  req_receipt_1_arg;
	t_string  *result_2;
	t_pair  req_1_arg;
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
	size_t encrypt_len;
	unsigned char *buf;
	FILE *file;

	clnt = clnt_create (host, REQ_PROG, REQ_VERS, "tcp");
	if (clnt == NULL) {
		clnt_pcreateerror (host);
		exit (EXIT_FAILURE);
	}

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
	if ((encrypt_len = RSA_public_encrypt(strlen(clearString)+1, 
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
	Base64Encode(encryptedString, encrypt_len, 
				&base64EncodedEncryptedString);
	strcpy(clientReq, base64EncodedEncryptedString);
	addToken(clientReq, getToken(request, TOKEN_ID_PUBLIC_KEY, token));

	req_receipt_1_arg.data = clientReq;
	printf("[1]::RPC: Client requesting server to provide invoice "
				"for PPC call: \n%s\n",
		request);

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
	Base64Decode(token, &buf, &encrypt_len);
	if (RSA_private_decrypt(encrypt_len, buf, clearString,
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
		sessionKey = cl_string_to_session_key (
				serverSessionKeyTokenString);

		// get label identifying this transaction
		if (getToken(clearString, TOKEN_RETURN_ID_LABEL, 
						labelString) == NULL) {
			printf("Missing label from server\n");
			exit (EXIT_FAILURE);
		}
		label = cl_string_to_label(labelString);

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
		if (cl_pay_invoice(bolt11, proofOfPayment) == FAILED) {
			printf("Payment failed for blot11: %s\n", bolt11);
			exit (EXIT_FAILURE);
		}
	}
// ###MKG client must parse return from 1st RPC and pass it as 
//      authorization in 2nd RPC)
//	req_1_arg.authorizationLabeldInvoice = invoice->data;  
//      ###MKG Fix THis */
//	req_1_arg.data = request;

//	printf("[7]::RPC: Client requesting service from server\n");
//	result_2 = req_1(&req_1_arg, clnt);
//	if (result_2 == (t_string *) NULL) {
//		clnt_perror (clnt, "call failed");
//	}
//	else
//	{
//		printf("[12]::RPC: Client received result of query: %s\n", 
//				result_2->data);
//	}

	clnt_destroy (clnt);

	exit (EXIT_SUCCESS);
}

int
main (int argc, char *argv[])
{	
	char reqString[MAX_LINE];
	char out[MAX_TOKEN];
	int quantity = 0;
	reqString[0] = '\0';
	char *clientRSAPublicKey;
	RSA *clientKeypair;

	// allocate memory to hold client RSA public key
	clientRSAPublicKey = (char *) calloc(MAX_LINE, sizeof(char));
	if (clientRSAPublicKey == NULL) {
		printf("Out of memory...");
		exit (EXIT_FAILURE);
	}

	if (argc != 4) {
		printf ("usage: %s server_ip service_type quantity\n", 
					argv[0]);
		exit (EXIT_FAILURE);
	}

	// check to make sure quantity is valid
	if (!isQuantityValid(argv[3]))
		printf("usage: invalid quantity specified: %s\n", 
					argv[3]);

	printf("Client initialting Pay Per Call (PPC) request to %s "
					"for %d %s.\n",
		argv[1], atoi(argv[3]), argv[2]);

	strcpy(reqString, argv[2]);
	addToken(reqString, argv[3]);


	// Add authorization code
	cl_make_authorization_code(&authCode);
	addToken(reqString, cl_auth_code_to_string(&authCode, out));

	clientKeypair = RSA_new();
	genRSAKeyPair(clientKeypair);
	rsaToPemPublicKeyString(clientKeypair, clientRSAPublicKey);

	addToken(reqString, clientRSAPublicKey);
	free(clientRSAPublicKey);

	ppc_request (argv[1], reqString, clientKeypair);

	RSA_free(clientKeypair);
}
