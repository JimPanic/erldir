%%%----------------------------------------------------------------------
%%% File    : dns_rr
%%% Author  : Stuart Jackson <sjackson@simpleenigma.com> [http://www.simpleenigma.com]
%%% Purpose : DNS Resource Record Encoding
%%% Created : 2007-01-06
%%% Updated : 2007-01-07
%%%----------------------------------------------------------------------
-module(dns_rr).

-include("dns.hrl").
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
