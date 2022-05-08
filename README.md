# pg_websocket
PostgreSQL extension that adds support for WebSocket connections to a database. Supports standards PostgreSQL protocol in a binary WebSocket connection.

Use with a WebSocket PostgreSQL client like [pegsocket.js](https://github.com/alaisi/pegsocket.js).

## Installation

Building the extension

```bash
$ make
$ sudo make install
```

Setup ```postgresql.conf```
```
shared_preload_libraries = 'pg_websocket'

## Optional: port to listen for WebSocket connections
# websocket.port = 15432
## Optional: backend database host to pass traffic to
# websocket.pg_host = localhost
## Optional: backend database port to pass traffic to
# websocket.pg_port = 5432
```
