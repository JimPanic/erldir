%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        DNS server Encoding
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
-module(dns_enc).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").

-export([encode/1,decode/1]).
-export([encode_header/1,decode_header/1,encode_question/1,decode_question/1]).
-export([domain_to_labels/1,labels_to_domain/1]).
-export([encode_list/1,null_pos/1]).

%-compile(export_all).

%%--------------------------------------------------------------------
%% Function: encode(Message)
%%           Message = term - Message record from dns.hrl
%% Descrip.: Encode a DNS Message
%% Returns : Binary
%%--------------------------------------------------------------------
encode(Message) when is_record(Message,message) -> 
	H = Message#message.header,
	Header = encode_header(H#header{qdcount=length(Message#message.question)}),
	Question = encode_question(Message#message.question),
	Answer = dns_rr:encode(Message#message.answer),
	Authority = dns_rr:encode(Message#message.authority),
	Additional = dns_rr:encode(Message#message.additional),
	<<Header/binary,Question/binary,Answer/binary,Authority/binary,Additional/binary>>.

%%--------------------------------------------------------------------
%% Function: decode(Binary)
%%           Binary - binary()
%% Descrip.: Decode a DNS Message
%% Returns : Message = term - Message record from dns.hrl
%%--------------------------------------------------------------------
decode(Binary) when is_binary(Binary) ->
	<<H:12/binary,QBODY/binary>> = Binary,
	Header = decode_header(H),
	{Question,RBODY} = decode_question(QBODY,Header#header.qdcount),
	{Answers,Authority,Additional} = dns_rr:decode(RBODY,Header#header.ancount,Header#header.nscount,Header#header.arcount),
	#message{header=Header,question=Question,answer=Answers,authority=Authority,additional=Additional}.

%%--------------------------------------------------------------------
%% Function: encode_header(Header)
%%           Header = term - Header record from dns.hrl
%% Descrip.: Encode a DNS Message Header
%% Returns : Binary
%%--------------------------------------------------------------------

encode_header(Header) when is_record(Header,header) ->
	ID = Header#header.id,
	QR = Header#header.qr,
	OPCODE = Header#header.opcode,
	AA = Header#header.aa,
	TC = Header#header.tc,
	RD = Header#header.rd,
	RA = Header#header.ra,
	Z = Header#header.z,
	RCODE = Header#header.rcode,
	QDCOUNT = Header#header.qdcount,
	ANCOUNT = Header#header.ancount,
	NSCOUNT = Header#header.nscount,
	ARCOUNT = Header#header.arcount,
	<<ID:16,QR:1,OPCODE:4,AA:1,TC:1,RD:1,RA:1,Z:3,RCODE:4,QDCOUNT:16,ANCOUNT:16,NSCOUNT:16,ARCOUNT:16>>.

%%--------------------------------------------------------------------
%% Function: decode_header(Binary)
%%           Binary - binary()
%% Descrip.: Decode a DNS Message Header
%% Returns : Header = term() - Header record from dns.hrl
%%--------------------------------------------------------------------

decode_header(Binary) when is_binary(Binary) ->
	<<ID:16,QR:1,OPCODE:4,AA:1,TC:1,RD:1,RA:1,Z:3,RCODE:4,QDCOUNT:16,ANCOUNT:16,NSCOUNT:16,ARCOUNT:16>> = Binary,
	#header{id=ID,qr=QR,opcode=OPCODE,aa=AA,tc=TC,rd=RD,ra=RA,z=Z,rcode=RCODE,
			qdcount=QDCOUNT,ancount=ANCOUNT,nscount=NSCOUNT,arcount=ARCOUNT}.

%%--------------------------------------------------------------------
%% Function: encode_question(Question)
%%           Question = term - Question record from dns.hrl
%% Descrip.: Encode a DNS Message Question
%% Returns : Binary
%%--------------------------------------------------------------------

encode_question(List) when is_list(List) -> 
	L = lists:foldl(fun(Q,Acc) -> [encode_question(Q)|Acc] end,[],lists:reverse(List)),
	encode_list(L);

encode_question(Question) when is_record(Question,question) ->
	if
		Question#question.qname == [] -> QNAME = domain_to_labels(".");
		true -> QNAME = domain_to_labels(Question#question.qname)
	end,
	QTYPE = Question#question.qtype,
	QCLASS = Question#question.qclass,
	<<QNAME/binary,QTYPE:16,QCLASS:16>>.
	
%%--------------------------------------------------------------------
%% Function: decode_question(Binary)
%%           Binary - binary()
%% Descrip.: Decode a DNS Message Question
%% Returns : list of Question record from dns.hrl
%%--------------------------------------------------------------------

decode_question(Binary,Count) -> decode_question(Binary,Count,[]).
decode_question(Binary,0,Acc) -> {lists:reverse(Acc),Binary};
decode_question(Binary,Count,Acc) ->
	QSIZE = null_pos(Binary) + 4,
	<<Q:QSIZE/binary,RBODY/binary>> = Binary,
	decode_question(RBODY,Count-1,[decode_question(Q)|Acc]).

decode_question(Binary) when is_binary(Binary) ->
	QNAME_SIZE = size(Binary) - 4,
	<<QNAME:QNAME_SIZE/binary,QTYPE:16,QCLASS:16>> = Binary,
	if
		is_binary(QNAME) -> #question{qname=labels_to_domain(QNAME),qtype=QTYPE,qclass=QCLASS};
		true -> #question{qname=QNAME,qtype=QTYPE,qclass=QCLASS}
	end.

%%--------------------------------------------------------------------
%% Function: domain_to_labels(Domain)
%%           Domain = list() - Domain Name String
%% Descrip.: Converts a domain name into a binary label
%% Returns : binary()
%%--------------------------------------------------------------------

domain_to_labels(DomainName) when is_atom(DomainName) -> domain_to_labels(atom_to_list(DomainName));
domain_to_labels(DomainName) -> 
	List = string:tokens(DomainName,[46]),
	Labels = lists:foldl(fun(L,Acc) -> [length(L),L|Acc] end,[],lists:reverse(List)),
	L = lists:append([lists:flatten(Labels),[0]]),
	list_to_binary(L).

%%--------------------------------------------------------------------
%% Function: labels_to_domain(Binary)
%%           Binary = binary()
%% Descrip.: Converts a binary label into a domain name
%% Returns : list() - Domain Name String
%%--------------------------------------------------------------------

labels_to_domain(Binary) when is_binary(Binary) -> labels_to_domain(binary_to_list(Binary));
labels_to_domain(List)   when is_list(List) -> labels_to_domain(List,[]).

labels_to_domain([0],Acc) -> 
	R = lists:reverse(lists:delete([46],Acc)),
	lists:flatten(R);
labels_to_domain([H|T],Acc) ->
	{Label,Rest} = lists:split(H,T),
	labels_to_domain(Rest,[[46],Label|Acc]).

%%--------------------------------------------------------------------
%% Function: null_pos(Binary)
%%           Binary = binary()
%% Descrip.: Finds first position of a ASCII NULL (0) in a binary term
%% Returns : integer - position of ASCII NULL (0)
%%--------------------------------------------------------------------

null_pos(Binary) ->
	List = binary_to_list(Binary),
	string:chr(List,0).

%%--------------------------------------------------------------------
%% Function: encode_list(List)
%%           List = list()
%% Descrip.: Concatenates a List of binary objects into one binary object
%% Returns : binary
%%--------------------------------------------------------------------

encode_list(List) ->
	List2 = lists:map(fun(B) -> binary_to_list(B) end,List),
	list_to_binary(lists:flatten(List2)).
