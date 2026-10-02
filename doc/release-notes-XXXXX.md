HTTP
----

RPC and REST interfaces can bind to unix sockets where supported by the platform.
Configure with `-rpcbind=unix:/absolute/filesystem/path` which will override
the default TCP localhost socket.

`bitcoin-cli` can connect to unix sockets with `-rpcconnect=unix:/absolute/filesystem/path`