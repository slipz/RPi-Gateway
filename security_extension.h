//openssl headers
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

void
hash_sign_GooseMessage(uint8_t* GooseMessage, unsigned char* key);