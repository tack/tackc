
OPENSSL_INCLUDE = /Users/trevp/Downloads/openssl-1.0.0d/include/
OPENSSL_LIB = /Users/trevp/Downloads/openssl-1.0.0d/libcrypto.a

tackc:  Makefile TackBreakSig.h TackBreakSig.c TackExtension.h TackExtension.c \
		TackMain.c TackOpenSSL.h TackOpenSSL.c TackRetval.h TackRetval.c \
		Tack.h Tack.c TackUtil.h TackUtil.c
	gcc -Wall -std=c99 -o tackc \
		-I$(OPENSSL_INCLUDE) \
	    $(OPENSSL_LIB) \
		TackBreakSig.c TackExtension.c TackMain.c TackOpenSSL.c TackRetval.c \
		Tack.c TackUtil.c

#		-I/Users/trevp/Downloads/openssl-1.0.0d/include/ \
#	    /Users/trevp/Downloads/openssl-1.0.0d/libcrypto.a \
