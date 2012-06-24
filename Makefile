
HEADERS = src/Tack.h src/TackExtension.h src/TackRetval.h \
	src/TackBreakSig.h src/TackUtil.h \
	src/TackCryptoFuncs.h

SRCS = src/Tack.c src/TackExtension.c src/TackRetval.c \
	src/TackBreakSig.c src/TackUtil.c \
	src/TackMain.c \

DEFINES = 
INCLUDEDIRS = -I/opt/local/include
LIBDIRS = -L/opt/local/lib
LIBS = 

ifdef TACKC_OPENSSL
HEADERS += src/TackOpenSSL.h
SRCS += src/TackOpenSSL.c
DEFINES += -DTACKC_OPENSSL
LIBS += -lcrypto
endif

ifdef TACKC_NSS
HEADERS += src/TackNss.h
SRCS += src/TackNss.c
DEFINES += -DTACKC_NSS
INCLUDEDIRS += -I/opt/local/include/nspr/ -I/opt/local/include/nss
LIBDIRS += -L/opt/local/lib/nss/
LIBS += -lnss3
endif


tackc:  Makefile $(HEADERS) $(SRCS)
	gcc -Wall -std=c99 -o tackc \
	$(DEFINES) $(INCLUDEDIRS) $(LIBDIRS) $(LIBS) $(SRCS)

clean:
	rm -f tackc
