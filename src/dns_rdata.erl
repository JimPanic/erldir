%%%----------------------------------------------------------------------
%%% File    : dns_rdata
%%% Author  : Stuart Jackson <sjackson@simpleenigma.com> [http://www.simpleenigma.com]
%%% Purpose : DNS Resource Record Data Encoding
%%% Created : 2007-01-06
%%% Updated : 2007-01-07
%%%----------------------------------------------------------------------
-module(dns_rdata).

-include("dns.hrl").
-export([encode/2,decode/2]).
%-compile(export_all).

%%--------------------------------------------------------------------
%% Function: encode(Type,Data)
%%           Type = integer() = 1-255 defining Resource Record Type
%%           Data = term() - RDATA for Resource Record
%% Descrip.: Encode DNS Resource Record RDATA into binary
%% Returns : Binary
%%--------------------------------------------------------------------
encode(Type,Data) ->
	case Type of
		1  -> encode_ip(Data);      % Type:A
		6  -> encode_soa(Data);     % Type:SOA
		15 -> encode_mx(Data);      % Type:MX
		16 -> list_to_binary(Data); % Type:TXT
		_Other -> dns_enc:domain_to_labels(Data)
	end.

%%--------------------------------------------------------------------
%% Function: decode(Type,Binary)
%%           Type = integer() = 1-255 defining Resource Record Type
%%           Binary = binary()
%% Descrip.: Decode binary into DNS Resource Record RDATA
%% Returns : term() - RDATA as defined for each Resource Record type
%%--------------------------------------------------------------------

decode(Type,Binary) when is_binary(Binary) ->
	case Type of
		1  -> decode_ip(Binary);      % Type:A
		6  -> decode_soa(Binary);     % Type:SOA
		15 -> decode_mx(Binary);      % Type:MX
		16 -> binary_to_list(Binary); % Type:TXT
		_Other -> dns_enc:labels_to_domain(Binary)
	end.

%%--------------------------------------------------------------------
%% Function: encode_ip(IpAddress)
%%           IpAddress = [List|Tuple|Integer]
%% Descrip.: Encode an IP Address into a 32bit binary term
%% Returns : Binary
%%--------------------------------------------------------------------
encode_ip(IP) when is_list(IP) -> 
	case inet_parse:address(IP) of
		{error,Reason} -> {error,Reason};
		{ok,IP_Tuple} -> encode_ip(IP_Tuple)
	end;
encode_ip(IP) when is_tuple(IP) -> 
	List = tuple_to_list(IP),
	list_to_binary(List);
encode_ip(IP) when is_integer(IP) -> <<IP:32>>.

%%--------------------------------------------------------------------
%% Function: decode_ip(Binary)
%%           Binary = binary()
%% Descrip.: Decode a 32bit binary term into an IP Address Tuple
%% Returns : Tuple
%%--------------------------------------------------------------------
decode_ip(Binary) when is_binary(Binary) ->
	List = binary_to_list(Binary),
	list_to_tuple(List).

%%--------------------------------------------------------------------
%% Function: encode_mx({Pref,Domain})
%%           Pref   = integer MX preference
%%           Domain = Domain Name for MX
%% Descrip.: Encode MX RDATA into binary
%% Returns : Binary
%%--------------------------------------------------------------------
encode_mx({Pref,Domain}) ->
	D = dns_enc:domain_to_labels(Domain),
	<<Pref:16,D/binary>>.
%%--------------------------------------------------------------------
%% Function: encode_mx(Binary)
%%           Binary = binary()
%% Descrip.: Decode MX RDATA from binary
%% Returns : {integer(),list()} = {Pref,Domain}
%%--------------------------------------------------------------------
decode_mx(Binary) when is_binary(Binary) ->
	<<Pref:16,D/binary>> = Binary,
	{Pref,dns_enc:labels_to_domain(D)}.
%%--------------------------------------------------------------------
%% Function: encode_soa(SOA)
%%           SOA = term() - soa record from dns.hrl
%% Descrip.: Encode SOA RDATA into binary
%% Returns : Binary
%%--------------------------------------------------------------------
encode_soa(SOA) when is_record(SOA,soa) ->
	MNAME   = dns_enc:domain_to_labels(SOA#soa.mname),
	RNAME   = dns_enc:domain_to_labels(SOA#soa.rname),
	SERIAL  = SOA#soa.serial,
	REFRESH = SOA#soa.refresh,
	RETRY   = SOA#soa.retry,
	EXPIRE  = SOA#soa.expire,
	MINIMUM = SOA#soa.minimum,
	<<MNAME/binary,RNAME/binary,SERIAL:32,REFRESH:32,RETRY:32,EXPIRE:32,MINIMUM:32>>.
%%--------------------------------------------------------------------
%% Function: decode_mx(Binary)
%%           Binary = binary()
%% Descrip.: Decode SOA RDATA from binary
%% Returns : SOA = term() - soa record from dns.hrl
%%--------------------------------------------------------------------
decode_soa(Binary) when is_binary(Binary) ->
	{MNAME_SIZE,RNAME_SIZE} = decode_soa_positions(Binary),
	<<MNAME:MNAME_SIZE/binary,RNAME:RNAME_SIZE/binary,SERIAL:32,REFRESH:32,RETRY:32,EXPIRE:32,MINIMUM:32>> = Binary,
	#soa{mname=dns_enc:labels_to_domain(MNAME),rname=dns_enc:labels_to_domain(RNAME),
		serial=SERIAL,refresh=REFRESH,retry=RETRY,expire=EXPIRE,minimum=MINIMUM}.
%%--------------------------------------------------------------------
%% Function: decode_soa_positions(Binary)
%%           Binary = binary()
%% Descrip.: Finds length of both varialbe length parts in the SOA record
%% Returns : {integer(),integer()}
%%--------------------------------------------------------------------
decode_soa_positions(Binary) ->
	List = binary_to_list(Binary),
	[MNAME,RNAME|_Rest] = string:tokens(List,[0]),
	{length(MNAME)+1,length(RNAME)+1}.
