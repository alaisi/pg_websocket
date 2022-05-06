EXTENSION = pg_websocket
DATA = pg_websocket--1.0.sql
DATA_built = 

MODULE_big = pg_websocket
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))
PG_CPPFLAGS = --std=c11 -Wall -Wextra -pedantic -Wno-unused-parameter -Wno-declaration-after-statement
SHLIB_LINK = -lcrypto

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
INCLUDEDIR = $(shell $(PG_CONFIG) --includedir-server)
include $(PGXS)

standalone: $(OBJS)
	$(CC) -o test $(OBJS) -L$(shell $(PG_CONFIG) --pkglibdir)  $(SHLIB_LINK) -lpgcommon

format:
	@clang-format --verbose -i \
		-style='{BasedOnStyle: llvm, IndentWidth: 4, ColumnLimit: 80, AlignOperands: Align, AlignAfterOpenBracket: Align, AllowShortFunctionsOnASingleLine: None, BreakBeforeBinaryOperators: true, BinPackParameters: false, BinPackArguments: false, PenaltyReturnTypeOnItsOwnLine: 99, PenaltyBreakBeforeFirstCallParameter: 99, PointerAlignment: Left, SpaceAfterCStyleCast: true}' \
		src/*.c
