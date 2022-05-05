
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fmgr.h"
#include "postgres.h"
#include "postmaster/bgworker.h"
#include "postmaster/postmaster.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

extern void _PG_init(void);
extern void _PG_fini(void);
void pg_websocket_main(Datum arg);

static void pg_websocket_sigterm(SIGNAL_ARGS) {
    ereport(LOG, (errmsg("pg_websocket sigterm")));
}

void pg_websocket_main(Datum arg) {
    ereport(LOG, (errmsg("pg_websocket_main")));

    pqsignal(SIGTERM, pg_websocket_sigterm);
    pqsignal(SIGINT, SIG_IGN);
    BackgroundWorkerUnblockSignals();

    ereport(LOG, (errmsg("pg_websocket_main starting")));
}

void _PG_init(void) {
    ereport(LOG, (errmsg("pg_websocket started")));

    BackgroundWorker worker;
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = 60;
    worker.bgw_notify_pid = 0;
    sprintf(worker.bgw_name, "pg_websocket");
    sprintf(worker.bgw_library_name, "pg_websocket");
    sprintf(worker.bgw_function_name, "pg_websocket_main");

    RegisterBackgroundWorker(&worker);
}

void _PG_fini(void) { ereport(LOG, (errmsg("pg_websocket stopped"))); }
