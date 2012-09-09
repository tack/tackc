
HEADERS = src/structures/Tack.h \
	src/structures/TackExtension.h \
	src/util/TackRetval.h \
	src/util/TackUtil.h \
	src/util/TackFingerprints.h \
	src/crypto/TackCryptoFuncs.h \
	src/processing/TackProcessing.h \
	src/store/TackStoreFuncs.h \
	src/store/TackPinList.h \
	src/test/TackTest.h


SRCS = src/structures/Tack.c \
	src/structures/TackExtension.c \
	src/util/TackRetval.c \
	src/util/TackUtil.c \
	src/util/TackFingerprints.c \
	src/processing/TackProcessing.c \
	src/store/TackStoreFuncs.c \
	src/store/TackPinList.c \
	src/test/TackMain.c \
	src/test/TackTestProcessing.c

DEFINES = 
INCLUDEDIRS = -I/opt/local/include -Isrc/structures -Isrc/util -Isrc/crypto -Isrc/store \
	-Isrc/processing -Isrc
LIBDIRS = -L/opt/local/lib
LIBS = 
COMPILER = gcc

ifdef TACKC_OPENSSL
HEADERS += src/crypto/TackOpenSSL.h
SRCS += src/crypto/TackOpenSSL.c
DEFINES += -DTACKC_OPENSSL
LIBS += -lcrypto
endif

ifdef TACKC_NSS
HEADERS += src/crypto/TackNss.h
SRCS += src/crypto/TackNss.c
DEFINES += -DTACKC_NSS
INCLUDEDIRS += -I/opt/local/include/nspr/ -I/opt/local/include/nss
LIBDIRS += -L/opt/local/lib/nss/
LIBS += -lnss3
endif

ifdef TACKC_CPP
COMPILER = g++
HEADERS += src/store/TackStore.h src/store/TackStoreDefault.h
SRCS += src/store/TackStore.cc src/store/TackStoreDefault.cc
DEFINES += -DTACKC_CPP
endif


tackc:  Makefile $(HEADERS) $(SRCS)
	$(COMPILER) -Wall -o tackc \
	$(DEFINES) $(INCLUDEDIRS) $(LIBDIRS) $(LIBS) $(SRCS)

clean:
	rm -f tackc
