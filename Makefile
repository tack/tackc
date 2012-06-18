
OPENSSL_INCLUDE = /Users/trevp/Downloads/openssl-1.0.0d/include/
OPENSSL_LIB = /Users/trevp/Downloads/openssl-1.0.0d/libcrypto.a

tackc:  Makefile src/TackBreakSig.h src/TackBreakSig.c src/TackExtension.h \
	src/TackExtension.c src/TackMain.c src/TackNss.h src/TackNss.c \
	src/TackOpenSSL.h src/TackOpenSSL.c src/TackRetval.h src/TackRetval.c \
	src/Tack.h src/Tack.c src/TackUtil.h src/TackUtil.c
	gcc -Wall -std=c99 -o tackc \
	-I$(OPENSSL_INCLUDE) \
	$(OPENSSL_LIB) \
	src/TackBreakSig.c src/TackExtension.c src/TackMain.c \
	src/TackNss.h src/TackNss.c src/TackOpenSSL.c src/TackRetval.c \
	src/Tack.c src/TackUtil.c
