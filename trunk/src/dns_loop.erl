-module(dns_loop).

-include("dns.hrl").

-compile(export_all).

start_link(From, Socket, Port, Type) ->proc_lib:spawn_link(?MODULE, init, [{From, Socket, Port, Type}]).

init({_From, Socket, _Port, _Type}) -> % Listen_Pid, Listen_Socket, Listen_Port, Type [tcp|udp]
%	dns_server:create(From, self(), Type),
	receive
		{udp,Socket,_IP,_InPortNo,Packet} -> 
			io:format("~p~n",[Packet]),
			Message = dns_enc:decode(Packet),
			io:format("~p~n",[Message]),
			gen_udp:close(Socket);
		{tcp,Socket,Packet} -> 
			io:format("~p~n",[Packet]),
			Message = dns_enc:decode(Packet),
			io:format("~p~n",[Message]),
			gen_tcp:close(Socket);
		{error,Reason} ->
			io:format("UDP Error: ~p~n",[Reason]),
			{error,Reason}
	end.	