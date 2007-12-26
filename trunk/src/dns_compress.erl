%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        DNS server compression
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
-module(dns_compress).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").

-export([compress/1,decompress/1]).
%-compile(export_all).

%%--------------------------------------------------------------------
%% Function: compress(Binary)
%%           Binary = binary()
%% Descrip.: Compress a binary message using DNS compress
%% Returns : binary() = compressed packet form
%%--------------------------------------------------------------------
compress(Binary) ->
	<<H:12/binary,QBody/binary>> = Binary,
	Header = dns_enc:decode_header(H),
	if
		Header#header.qdcount == 1 -> 
			case dns_enc:null_pos(QBody) of
				1 ->
					<<QName:8,QType:16,QClass:16,RRBody/binary>> = QBody,
					Q = <<QName:8,QType:16,QClass:16>>;
				N -> 
					QSIZE = N + 2,
					<<Q:QSIZE/binary,RRBody/binary>> = QBody
			end;
		true -> 
			Q = "",
			RRBody = ""
	end,
	RRList = c_r(RRBody,<<H/binary,Q/binary>>,Header#header.ancount + Header#header.nscount + Header#header.arcount),
	RRs = dns_enc:encode_list(RRList),
	<<H/binary,Q/binary,RRs/binary>>.

%%--------------------------------------------------------------------
%% Function: decompress(Binary)
%%           Binary = binary()
%% Descrip.: Decompress a binary message using DNS compress
%% Returns : binary() = compressed packet form
%%--------------------------------------------------------------------
decompress(Binary) ->
	<<H:12/binary,QBody/binary>> = Binary,
	Header = dns_enc:decode_header(H),
	if
		Header#header.qdcount == 1 -> 
			case dns_enc:null_pos(QBody) of
				1 ->
					<<QName:8,QType:16,QClass:16,RRBody/binary>> = QBody,
					Q = <<QName:8,QType:16,QClass:16>>;
				N -> 
					QSIZE = N + 2,
					<<Q:QSIZE/binary,RRBody/binary>> = QBody
			end;
		true -> 
			Q = "",
			RRBody = ""
	end,
	RRList = d_r(RRBody,Binary,Header#header.ancount + Header#header.nscount + Header#header.arcount),
	RRs = dns_enc:encode_list(RRList),
	<<H/binary,Q/binary,RRs/binary>>.

%%--------------------------------------------------------------------
%% Function: c_r(Binary,OBinary,Count)
%%           Binary  = binary()  - Resource Record Section of packet
%%           OBinary = binary()  - Original Binary Packet
%%           Count   = integer() - Number of REsource Receords
%% Descrip.: Compresses Labels in each Resoruce Record
%% Returns : binary() = compressed Resource Records
%%--------------------------------------------------------------------
c_r(Binary,OBinary,Count) -> c_r(Binary,OBinary,Count,[]).
c_r(_Binary,_OBinary,0,Acc) -> lists:reverse(Acc);
c_r(Binary,OBinary,Count,Acc) ->
	{Name,NRest} = label(Binary),
	<<TYPE:16,CLASS:16,TTL:32,RDLENGTH:16,RDATA:RDLENGTH/binary,Rest/binary>> = NRest,
	NewName = c_label(Name,OBinary,[],false),
	case TYPE of
		2 -> NewRdata = c_label(RDATA,OBinary,[],false);
		_ -> NewRdata = RDATA
	end,
	NewRDLength = size(NewRdata),
	case NewName of
		0 -> RR = <<NewName:8,TYPE:16,CLASS:16,TTL:32,NewRDLength:16,NewRdata/binary>>;
		_ -> RR = <<NewName/binary,TYPE:16,CLASS:16,TTL:32,NewRDLength:16,NewRdata/binary>>
	end,
	c_r(Rest,<<OBinary/binary,RR/binary>>,Count-1,[RR|Acc]).

%%--------------------------------------------------------------------
%% Function: d_r(Binary,OBinary,Count)
%%           Binary  = binary()  - Resource Record Section of packet
%%           OBinary = binary()  - Original Binary Packet
%%           Count   = integer() - Number of REsource Receords
%% Descrip.: Decompresses Labels in each Resoruce Record
%% Returns : binary() = uncompressed Resource Records
%%--------------------------------------------------------------------
d_r(Binary,OBinary,Count) -> d_r(Binary,OBinary,Count,[]).

d_r(_Binary,_OBinary,0,Acc) -> lists:reverse(Acc);
d_r(Binary,OBinary,Count,Acc) ->
	{DName,NRest} = label(Binary),
	Name = d_label(DName,OBinary),
	<<TYPE:16,CLASS:16,TTL:32,RDLENGTH:16,RDATA:RDLENGTH/binary,Rest/binary>> = NRest,
	case TYPE of
		2 -> NewRdata = d_label(RDATA,OBinary);
		_ -> NewRdata = RDATA
	end,
	NewRDLength = size(NewRdata),
	case Name of
		0 -> RR = <<Name:8,TYPE:16,CLASS:16,TTL:32,NewRDLength:16,NewRdata/binary>>;
		_ -> RR = <<Name/binary,TYPE:16,CLASS:16,TTL:32,NewRDLength:16,NewRdata/binary>>
	end,
	d_r(Rest,OBinary,Count-1,[RR|Acc]).

%%--------------------------------------------------------------------
%% Function: c_label(Binary)
%%           Binary = binary()
%% Descrip.: Recursive label compression
%% Returns : binary() = compressed label form
%%--------------------------------------------------------------------
c_label(0,_Packet,[],_Comp) -> 0;
c_label(<<0>>,Packet,Acc,Comp) -> 
	L = dns_enc:encode_list(lists:reverse(Acc)),
	if
		Comp -> c_label(L,Packet,[],false);
		true -> 
			case string:chr(binary_to_list(L),192) of
				0 -> <<L/binary,0>>;
				_ -> L
			end
	end;
c_label(Label,Packet,Acc,Comp) -> 
	case string:str(binary_to_list(Packet),binary_to_list(Label)) of
		0 -> 
			case string:chr(binary_to_list(Label),192) of
				0 ->
					<<Count:8,L:Count/binary,Rest/binary>> = Label,
					c_label(Rest,Packet,[<<Count:8,L/binary>>|Acc],Comp);					
				_ -> c_label(<<0>>,Packet,[Label|Acc],false)
			end;

		P -> 
			Pos = P-1,
			c_label(<<0>>,Packet,[<<192,Pos>>|Acc],true)
	end.

%%--------------------------------------------------------------------
%% Function: d_label(Binary)
%%           Binary = binary()
%% Descrip.: Recursive label decompression
%% Returns : binary() = decompressed label form
%%--------------------------------------------------------------------
d_label(0,_) -> 0;
d_label(Binary,Original) when is_binary(Binary), is_binary(Original) -> d_label(binary_to_list(Binary),binary_to_list(Original),[]).

d_label([H|T],Original,Acc) ->
	case H of
		192 -> 
			[Pos|_] = T,
			{_B,L} = lists:split(Pos,Original),
			Length = string:chr(L,0),
			{Label,_} = lists:split(Length,L),
			d_label([],Original,[Label|Acc]);
		N -> 
			{Part,Rest} = lists:split(N,T),
			d_label(Rest,Original,[Part,N|Acc])
	end;
d_label([],Original,Acc) -> 
	L = lists:flatten(lists:reverse(Acc)),
	case string:chr(L,192) of
		0 -> list_to_binary(L);
		_ -> d_label(list_to_binary(L),list_to_binary(Original))
	end.

%%--------------------------------------------------------------------
%% Function: label(Binary)
%%           Binary = binary()
%% Descrip.: correctly identifies a label in compressed or 
%%         : uncompressed form
%% Returns : {binary(),binary()} = binary label and rest of original binary
%%--------------------------------------------------------------------
label(Binary) ->
	<<C:8,_R/binary>> = Binary,
	if
		C == 192 ->
			<<Label:2/binary,Rest/binary>> = Binary;
		true ->
			case dns_enc:null_pos(Binary) of
				1 -> <<Label:8,Rest/binary>> = Binary;
				N -> 
					<<Label:N/binary,Rest/binary>> = Binary
			end
	end,
	{Label,Rest}.