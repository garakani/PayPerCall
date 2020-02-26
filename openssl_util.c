#include "proj.h"

void genRSAKeyPair(RSA *keypair) {
	BIGNUM *e;
	e = BN_new();
	BN_set_word(e, RSA_F4);
	
	if (!RSA_generate_key_ex(keypair, RSA_KEY_SIZE, e, NULL))
		exit (EXIT_FAILURE);

	BN_free(e);
	return;
}

void rsaToPemPrivateKeyString(RSA *keypair, char *pemPrivateKeyString) {
	BIO *private = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(private, keypair, NULL, NULL, 0, NULL, 
					NULL);
	size_t length = BIO_pending(private);
	BIO_read(private, pemPrivateKeyString, length);
	pemPrivateKeyString[length] = '\0';

	BIO_free(private);
	
	return;
}

void rsaToPemPublicKeyString(RSA *keypair, char *pemPublicKeyString) {
	BIO *public = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(public, keypair);
	size_t length = BIO_pending(public);
	BIO_read(public, pemPublicKeyString, length);
	pemPublicKeyString[length] = '\0';

	BIO_free(public);

	return;
}

void pemPublicKeyStringToRsa(RSA *keypair, char *pemPublicKeyString) {
	BIO *public = BIO_new(BIO_s_mem());
	BIO_write(public, pemPublicKeyString, strlen(pemPublicKeyString));
	PEM_read_bio_RSAPublicKey(public, &keypair, NULL, NULL);

	BIO_free(public);
}

void pemPublicKeyinFileToRsa(RSA *keypair, char *filename) {
	char pemPublicKeyString[BUF];
	FILE *file;
      	file = fopen(filename,"rb+");
      	if (file)
      	{
		fseek(file, 0, SEEK_END);
		long length = ftell(file);
		fseek(file, 0, SEEK_SET);
		size_t new_length = fread(pemPublicKeyString, sizeof(char), 
					length, file);
		pemPublicKeyString[new_length] = '\0';
          	fclose(file);
		pemPublicKeyStringToRsa(keypair, pemPublicKeyString);
      	}

	return;
}

void rsaToPemPublicKeyInFile(RSA *keypair, char *filename) {
	char pemPublicKeyString[BUF];
	FILE *file;
      	file = fopen(filename,"wb+");
      	if(file)
      	{
		rsaToPemPublicKeyString(keypair, pemPublicKeyString);
          	fputs(pemPublicKeyString, file);
          	fclose(file);
      	}

	return;
}

void copyRSAKeypair(RSA *rsa1, RSA *rsa2) {
	BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA_get0_key(rsa1, (const BIGNUM **) &n, (const BIGNUM **) &e, 
				(const BIGNUM **) &d);
	RSA_get0_factors(rsa1, (const BIGNUM **) &p, (const BIGNUM **) &q);
	RSA_get0_crt_params(rsa1, (const BIGNUM **) &dmp1, (const BIGNUM **) 
				&dmq1, (const BIGNUM **) &iqmp);

	BN_print_fp(stdout, n);
	printf("\n");
	BN_print_fp(stdout, e);
	printf("\n");
	BN_print_fp(stdout, d);
	printf("\n");
	BN_print_fp(stdout, p);
	printf("\n");
	BN_print_fp(stdout, q);
	printf("\n");
	BN_print_fp(stdout, dmp1);
	printf("\n");
	BN_print_fp(stdout, dmq1);
	printf("\n");
	BN_print_fp(stdout, iqmp);
	RSA_set0_key(rsa2, n, e, d);
	RSA_set0_factors(rsa2, p, q);
	RSA_set0_crt_params(rsa2, dmp1, dmq1, iqmp);

	return;
}

BIGNUM *getNextBigNumToken(FILE *file) {
	int length;
	unsigned char buffer[MAX_LINE];
	BIGNUM *p;
	p = BN_new();

	fgets(buffer, MAX_LINE-1, file);
	length = strlen(buffer);
	if (buffer[length-1]=='\n')
		buffer[length-1]='\0';
        BN_hex2bn(&p, buffer);

	return p;
}

RSA *getRSAKey() {
	static RSA *serverKeypair = NULL;
	BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	FILE *file;

	// Load or generate server RSA keypair, if needed
	if (serverKeypair == NULL) {

		serverKeypair = RSA_new();

		// load keypair from RSA file, if file exists
 		if (file = fopen (SERVER_KEY_PAIR_FILENAME, "rb")) {
			n = getNextBigNumToken(file);
			e = getNextBigNumToken(file);
			d = getNextBigNumToken(file);
			p = getNextBigNumToken(file);
			q = getNextBigNumToken(file);
			dmp1 = getNextBigNumToken(file);
			dmq1 = getNextBigNumToken(file);
			iqmp = getNextBigNumToken(file);
			RSA_set0_key(serverKeypair, n, e, d);
			RSA_set0_factors(serverKeypair, p, q);
			RSA_set0_crt_params(serverKeypair, dmp1, dmq1, iqmp);
		}

		// Generate key pair and store in file, if file does not 
		// already exist.
		// NOTE 1: Client needs to have a copy of the server's public 
		//         key PEM file to make requests. After generating this
		//         file here, the file containing server public key
		//	   must be transferred to client machine.
                //         before client requests can be processed on server.
		//         For demo code, the "server_key.pub" file is 
		//	   transferred manually from ".ppc" folder on server 
		// 	   to the ".ppc" folder on client machine.
                //         For production code, the server public key should be
		//	   provided to client via X.509 certificate and can be
		//	   verified up the certificate's signature chain to 
		//	   root signature. Also generated here is a 
		//	   "server_rsa" binary file, which resides 
                //         on server only and contains the server's 
		//	   private and public RSA keys.
		// NOTE 2: To regenerate new server RSA key pairs:
		//         1) bring down server,
                //         2) delete "key.pri" file from the ".ppc" directory 
		//	      on server.
		//         3) Make a client service request. This would 
		//	      generate a new keypair on server and store its 
		// 	      parameters in "key.pri".
                //            This also creates a public key pem file 
		//	      "server_pub.pem" which contains the server's 
		//	       public key.
                //         4) Distribute the new "server_pub.pem" file to 
		//	      client machine(s).
		else {
			genRSAKeyPair(serverKeypair);
     			file = fopen(SERVER_KEY_PAIR_FILENAME,"wb+");
      			if (file)
      			{
				// Store Server's private/public keypair 
				// parameters in file
				RSA_get0_key(serverKeypair, 
						(const BIGNUM **) &n, 
						(const BIGNUM **) &e, 
						(const BIGNUM **) &d);
				RSA_get0_factors(serverKeypair, 
						(const BIGNUM **) &p, 
						(const BIGNUM **) &q);
				RSA_get0_crt_params(serverKeypair, 
						(const BIGNUM **) &dmp1,
					 	(const BIGNUM **) &dmq1,
						(const BIGNUM **) &iqmp);
				BN_print_fp(file, n);
				fprintf(file, "\n");
				BN_print_fp(file, e);
				fprintf(file, "\n");
				BN_print_fp(file, d);
				fprintf(file, "\n");
				BN_print_fp(file, p);
				fprintf(file, "\n");
				BN_print_fp(file, q);
				fprintf(file, "\n");
				BN_print_fp(file, dmp1);
				fprintf(file, "\n");
				BN_print_fp(file, dmq1);
				fprintf(file, "\n");
				BN_print_fp(file, iqmp);
          			fclose(file);
				chmod(SERVER_KEY_PAIR_FILENAME, strtol("0400",
						0, 8));
      			}

			// Store public key in pem file and make it 
			// available to client
			rsaToPemPublicKeyInFile(serverKeypair, 
						SERVER_PUB_KEY_FILENAME);
			printf("The file %s must be transferred to .ppc folder"
						" on client machine(s).\n",
						SERVER_PUB_KEY_FILENAME);
		}
	}

	return serverKeypair;
}


char *
cl_RSA_encrypt(char *in, char *out, char *pemKey) {
	strcpy(out, in);  // ###MKG fix this later
	return out;
}

char *
cl_RSA_decrypt(char *in, char *out, RSA *keypair) {
	strcpy(out, in);  // ###MKG fix this later
	return out;
}

int
isQuantityValid(char *quantity) {
	int q = atoi(quantity);
	if (q > 0 && q < MAX_VALID_QUANTITY)
		return TRUE;
	else
		return FALSE;
}




