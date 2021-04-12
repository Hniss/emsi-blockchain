#include "hblk_crypto.h"

uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t *sig){
	EC_KEY *s_key = EC_KEY_new();

	if(!key || !msg)
		return (NULL);

	if(!EC_KEY_copy(s_key, key))
		return (NULL);
	if (!sig->len)
		return (NULL);	
	if(ECDSA_sign(EC_CURVE, msg, msglen, sig->sig, (unsigned int*)&sig->len, s_key)==0)
		return (NULL);

	return (sig->sig);


}


