-module(dns_lookup).

-include("dns.hrl").

-compile(export_all).


lookup(Address,Port,Packet) when is_binary(Packet) -> lookup(Address,Port,dns_enc:decode(Packet));
lookup(Address,Port,Message) when is_record(Message,message) ->
	io:format("Address: ~p~n Port: ~p~n Message~p~n",[Address,Port,Message]),
	ok.