// Reference: The code in this file originates from EclipseSource by Ian Bull with slight modifications
// See: 
// https://eclipsesource.com/blogs/2016/09/07/tutorial-code-signing-and-verification-with-openssl/

#include "proj.h"

size_t calcDecodeLength(const char* b64input) {
  	size_t len = strlen(b64input), padding = 0;

  	if (b64input[len-1] == '=' && b64input[len-2] == '=')
    		padding = 2;
  	else if (b64input[len-1] == '=') //last char is =
    	padding = 1;
  	return (len*3)/4 - padding;
}

void Base64Encode( const unsigned char* buffer, 
                   size_t length, 
                   char** base64Text) { 
  	BIO *bio, *b64;
  	BUF_MEM *bufferPtr;

  	b64 = BIO_new(BIO_f_base64());
  	bio = BIO_new(BIO_s_mem());
  	bio = BIO_push(b64, bio);

  	BIO_write(bio, buffer, length);
  	BIO_flush(bio);
  	BIO_get_mem_ptr(bio, &bufferPtr);
  	BIO_set_close(bio, BIO_NOCLOSE);
  	BIO_free_all(bio);

  	*base64Text=(*bufferPtr).data;
}

void Base64Decode(const char* b64message, unsigned char** buffer, 
			size_t* length) {
  	BIO *bio, *b64;

  	int decodeLen = calcDecodeLength(b64message);
  	*buffer = (unsigned char*)malloc(decodeLen + 1);
  	(*buffer)[decodeLen] = '\0';

  	bio = BIO_new_mem_buf(b64message, -1);
  	b64 = BIO_new(BIO_f_base64());
  	bio = BIO_push(b64, bio);

  	*length = BIO_read(bio, *buffer, strlen(b64message));
  	BIO_free_all(bio);
}

char* RSASignBase64(RSA* rsa, 
              const unsigned char* Msg, 
              size_t MsgLen) {

	unsigned char* EncMsg; 
	size_t MsgLenEnc;
	char* base64Text;
  	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  	EVP_PKEY* priKey  = EVP_PKEY_new();
  	EVP_PKEY_assign_RSA(priKey, rsa);

  	if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), 
				NULL,priKey)<=0) {
      		return NULL;
  	}
  	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      		return NULL;
  	}
  	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &MsgLenEnc) <=0) {
      		return NULL;
  	}
  	EncMsg = (unsigned char*)malloc(MsgLenEnc);
  	if (EVP_DigestSignFinal(m_RSASignCtx, EncMsg, &MsgLenEnc) <= 0) {
      		return NULL;
  	}

	Base64Encode(EncMsg, MsgLenEnc, &base64Text);

	free(EncMsg);

  	EVP_MD_CTX_destroy(m_RSASignCtx);
  	return base64Text;
}

_Bool RSAVerifySignature(RSA* rsa, 
                         unsigned char* MsgHash, 
                         size_t MsgHashLen, 
                         const char* Msg, 
                         size_t MsgLen, 
                         _Bool* Authentic) {
  	*Authentic = false;
  	EVP_PKEY* pubKey  = EVP_PKEY_new();
  	EVP_PKEY_assign_RSA(pubKey, rsa);
  	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  	if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, 
				EVP_sha256(),NULL,pubKey)<=0) {
    		return false;
  	}
  	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    		return false;
  	}
  	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, 
				MsgHashLen);
  	if (AuthStatus==1) {
    		*Authentic = true;
    		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    		return true;
  	} else if(AuthStatus==0){
    		*Authentic = false;
    		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    		return true;
  	} else{
    		*Authentic = false;
    		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    		return false;
  	}
}

_Bool verifySignature(RSA* publicRSA, char* plainText, 
				size_t plainTextLength, 
				char* signatureBase64) {
  	unsigned char* encMessage;
  	size_t encMessageLength;
  	_Bool authentic;

  	Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  	_Bool result = RSAVerifySignature(publicRSA, encMessage, 
				encMessageLength, plainText, 
				plainTextLength, &authentic);
	if (result == false) 
		printf("Signature verification operation failed\n");
	else if (authentic == false)
		printf("Signature failed to match\n");
		
  	return result & authentic;
}


