CC = gcc
CFLAGS = -Wall

sec: main3_testicmp.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/hmac_functions.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/gmac_functions.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/r_goose_security.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/aux_funcs.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/aes_crypto.c
	$(CC) $(CFLAGS) -o a.out main3_testicmp.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/hmac_functions.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/gmac_functions.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/r_goose_security.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/aux_funcs.c ../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/aes_crypto.c -I../R-GOOSE_SecLib/R-GOOSE_SecLib_1_0_0/src/ -lssl -lcrypto -lnfnetlink -lnetfilter_queue
