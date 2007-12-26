%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        DNS server Resource Record functions
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
-module(dns_rr).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").
-export([encode/1,decode/4,decode/2]).
% -compile(export_all).

%%--------------------------------------------------------------------
%% Function: encode(RR)
%%           RR = term - RR (Resource Record) record from dns.hrl
%% Descrip.: Encode a DNS Resource Record into binary
%% Returns : Binary
%%--------------------------------------------------------------------

encode(RR) when is_record(RR,rr) -> 
	NAME = dns_enc:domain_to_labels(RR#rr.name),
	TYPE = RR#rr.type,
	CLASS = RR#rr.class,
	TTL = RR#rr.ttl,
	RDATA = dns_rdata:encode(TYPE,RR#rr.rdata),
	RDLENGTH = size(RDATA),
	<<NAME/binary,TYPE:16,CLASS:16,TTL:32,RDLENGTH:16,RDATA/binary>>;
encode(List) when is_list(List) ->
	RRList = lists:map(fun(RR) -> encode(RR) end,List),
	dns_enc:encode_list(RRList).

%%--------------------------------------------------------------------
%% Function: decode(Binary)
%%           Binary - binary()
%% Descrip.: Decode binary into a DNS Resource Record
%% Returns : RR = term - RR (Resource Record) record from dns.hrl
%%--------------------------------------------------------------------

decode(Binary,ANCount,NSCount,ARCount) ->
	{Answers,Binary2} = decode(Binary,ANCount),
	{Authority,Binary3} = decode(Binary2,NSCount),
	{Additional,_Rest} = decode(Binary3,ARCount),
	{Answers,Authority,Additional}.


decode(Binary,Count) -> decode(Binary,Count,[]).

decode(Binary,0,Acc) -> {Acc,Binary};
decode(Binary,Count,Acc) -> 
	NAME_SIZE = dns_enc:null_pos(Binary),
	<<NAME:NAME_SIZE/binary,TYPE:16,CLASS:16,TTL:32,RDLENGTH:16,RDATA:RDLENGTH/binary,REST/binary>> = Binary,
	RR = #rr{name=dns_enc:labels_to_domain(NAME),type=TYPE,class=CLASS,ttl=TTL,rdlength=RDLENGTH,rdata=dns_rdata:decode(TYPE,RDATA)},
	decode(REST,Count-1,[RR|Acc]).
