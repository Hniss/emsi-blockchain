#include "hblk_crypto.h"

int ec_save(EC_KEY *key, char const *folder){
	char path[BUFSIZ];
	FILE *f;	


	mkdir(folder, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	sprintf(path, "%s/%s", folder, PUB_FILENAME);
	f = fopen(path, "w");

	if(!f)
	{
		return 0;
	}

	if(!PEM_write_EC_PUBKEY(f, key))
	{
		fclose(f);
		return 0;
	}
	
	fclose(f);
	
	sprintf(path, "%s/%s", folder, PRI_FILENAME);
	
	f = fopen(path, "w");
	
	if(!f)
	{
		return 0;
	}


	if(!PEM_write_ECPrivateKey(f, key, NULL, NULL, 0, NULL, NULL))
	{
		fclose(f);
		return 0;
	}
	
	fclose(f);
	return 0;

}
