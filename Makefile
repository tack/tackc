
HEADERS = src/Tack.h src/TackExtension.h src/TackRetval.h \
	src/TackBreakSig.h src/TackUtil.h \
	src/TackCryptoFuncs.h src/TackFingerprints.h

SRCS = src/Tack.c src/TackExtension.c src/TackRetval.c \
	src/TackBreakSig.c src/TackUtil.c \
	src/TackMain.c src/TackFingerprints.c

DEFINES = 
INCLUDEDIRS = -I/opt/local/include
LIBDIRS = -L/opt/local/lib
LIBS = 
COMPILER = gcc

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

ifdef TACKC_CPP
COMPILER = g++
HEADERS += src/TackStore.h src/TackStoreDefault.h
SRCS += src/TackStore.cc src/TackStoreDefault.cc
DEFINES += -DTACKC_CPP
endif


tackc:  Makefile $(HEADERS) $(SRCS)
	$(COMPILER) -Wall -o tackc \
	$(DEFINES) $(INCLUDEDIRS) $(LIBDIRS) $(LIBS) $(SRCS)

clean:
	rm -f tackc
