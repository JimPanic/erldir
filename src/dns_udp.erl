-module(dns_udp).

-include("dns.hrl").

-compile(export_all).


start() -> start(53).
start(Port) ->
	{ok,Socket} = gen_udp:open(Port,[binary,{active,false}]),
	io:format("Opening Socket: ~p~n",[Socket]),
	proc_lib:spawn(?MODULE,do_recv,[Socket]).


do_recv(Socket) -> do_recv(Socket,infinity).
do_recv(Socket,Timeout) ->
	case gen_udp:recv(Socket, 0 , Timeout) of
		{ok,{Address,Port,Packet}} -> 
			proc_lib:spawn(dns_lookup,lookup,[Address,Port,Packet]),
			do_recv(Socket,Timeout);
		{error,timeout} -> do_recv(Socket,Timeout);
		{error,closed} -> io:format("Error: Closed Socket ~p~n",[Socket]);
		{error,Reason} -> io:format("Error: Closed Socket ~p~nReason: ~p~n",[Socket,Reason])
	end.


question(IP,Message) -> question(IP,53,Message).

question(IP,Port,Message) when is_record(Message,message) -> question(IP,Port,dns_enc:encode(Message));
question(IP,Port,Packet) when is_binary(Packet) ->
	{ok,Socket} = gen_udp:open(53,[binary]),
	io:format("Opening Socket: ~p~n",[Socket]),
	gen_udp:send(Socket,IP,Port,Packet),
	io:format("Sent Packet ...~n"),
	receive
		{udp,Socket,IP,Port,Packet} -> R = dns_enc:decode(Packet)
		after 
			2000 -> 
			io:format("Timeout after 2 seconds~n"),
			R = ""
	end,	
	gen_udp:close(Socket),
	R.

respond(Address,Port,Message) when is_record(Message,message) -> respond(Address,Port,dns_enc:encode(Message));
respond(Address,Port,Packet) ->
	Socket = "Find out what the socket is",
	gen_udp:send(Socket,Address,Port,Packet).





root() ->
	{ok,Socket} = gen_udp:open(53,[binary]),
	P = dns_cache:get_root(),
	gen_udp:send(Socket,?A_ROOT_SERVERS_NET,53,P),
	receive
		{udp,Socket,_IP,_InPortNo,Packet} -> ok
	end,	
	gen_udp:close(Socket),
	Packet.
