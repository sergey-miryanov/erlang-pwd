ERL_INTERFACE=/usr/local/lib/erlang/lib/erl_interface-3.6.5
ERL_ROOT=/usr/local/lib/erlang
OUTPUT=../ebin/pwd_drv.so
LDFLAGS=-shared -fPIC -undefined -lei -lerl_interface -L${ERL_INTERFACE}/lib 
CFLAGS=-o ${OUTPUT} -I${ERL_ROOT}/usr/include -I${ERL_INTERFACE}/include/ -Wall -W -Wno-unused-parameter

all:
	gcc pwd_drv.c ${LDFLAGS} ${CFLAGS} -O2

debug:
	gcc pwd_drv.c ${LDFLAGS} ${CFLAGS} -ggdb -O0
