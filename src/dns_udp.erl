%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        DNS server UDP functions
%%% @reference  See <a href="http://erlsoft.org/modules/erldir" target="_top">Erlang Software Framework</a> for more information
%%% @reference See <a href="http://erldir.googlecode.com" target="_top">ErlDir Google Code Repository</a> for more information
%%% @version    0.0.2
%%% @since      0.0.1
%%% @end
%%%
%%%
%%% The MIT License
%%%
%%% Copyright (c) 2007 Stuart Jackson, Simple Enigma, Inc. All Righs Reserved
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a copy
%%% of this software and associated documentation files (the "Software"), to deal
%%% in the Software without restriction, including without limitation the rights
%%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%%% copies of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in
%%% all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%%% THE SOFTWARE.
%%%
%%%
%%%---------------------------------------------------------------------------------------
-module(dns_udp).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").

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
