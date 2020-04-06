/* Important info

	how-to-compile-c-file-with-openssl-includes @ stackoverflow

*/

#include <stdio.h>
#include <string.h>

//openssl headers
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "security_extension.h"

void
hash_sign_GooseMessage(uint8_t* GooseMessage, unsigned char* key){

	// Parse GooseMessage, extract only to-hash/sign part

	int bufPos = 18; // Init GoosePdu index


	int pduSize = (GooseMessage[20]<<8)+GooseMessage[21]; // Get GoosePdu Size

	// Debug
	printf("pduSize - %d\n",pduSize);

	// Copy GoosePdu to hash
	uint8_t* toHash = malloc(sizeof(uint8_t)*pduSize);



	memcpy(toHash, &GooseMessage[18], pduSize);



	/*for(int i=0; i<400; i++){
		GooseMessage[i] = 0;
	}

	int l;
    for(l = 0; l<1024; l++){
        printf("%02X ", GooseMessage[l]);
    }
    printf("\n\n\n");*/

	// Hash+Sign parsed data
	unsigned char* result;
	// Sizeof(key)-1 if: key is char*
	//result = HMAC(EVP_sha256(), key, sizeof(key)-1, toHash, sizeof(toHash), NULL, NULL);


	/*const char hexstring[] = "", *pos = hexstring;
	unsigned char val[12];
	size_t count = 0;

	for(count = 0; count < sizeof(val)/sizeof(val[0]), count++){
		char buf[5] = {"0", "x", pos[0], pos[1], 0}
		val[count] = strtol(buf, NULL, 0);
		pos += 2 * sizeof(char);
	}*/


	result = HMAC(EVP_sha256(),"Jefe", sizeof("Jefe")-1, "what do ya want for nothing?", sizeof("what do ya want for nothing?")-1, NULL, NULL);

	for(int j = 0; j<32; j++){
		printf("%02x",result[j]);
	}

	//printf("sha - %s\n", result);


	// Reformat GooseMessage with extended data (hmac+security fields)

	// Return hashed+signed GooseMessage	
}