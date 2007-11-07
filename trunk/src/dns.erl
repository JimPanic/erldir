-module(dns).


-compile(export_all).

s() -> dns_server:start_link(53).