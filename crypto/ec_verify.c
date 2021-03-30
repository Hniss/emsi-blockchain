#include "hblk_crypto.h"

int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t const *sig){

	EC_KEY *s_key = EC_KEY_new();

	if(!key || !msg || !sig)
		return 0;

	if(!EC_KEY_copy(s_key, key))
		return 0;

	if(ECDSA_verify(0, msg, msglen, sig->sig, sig->len, s_key)!=1)
		return 0;
	
	return 1;
}
