bin_PROGRAMS = doitclient
doitclient_SOURCES = doitclient.c doitlib.c
doitclient_LDADD = $(LIBOBJS)

noinst_PROGRAMS = protocol-test
protocol_test_SOURCES = doitlib.c
protocol_test_CPPFLAGS = -DTESTMODE

check: protocol-test
	./protocol-test
