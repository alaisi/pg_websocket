EXTENSION = pg_websocket
DATA = pg_websocket--1.0.sql
DATA_built = 

MODULE_big = pg_websocket
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))
PG_CPPFLAGS = --std=c11 -Wall -Wextra -Wno-unused-parameter -Wno-declaration-after-statement
SHLIB_LINK = -lz -lpthread -lrt

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
INCLUDEDIR = $(shell $(PG_CONFIG) --includedir-server)
include $(PGXS)
