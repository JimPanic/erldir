%%%----------------------------------------------------------------------
%%% File    : dns_catalog
%%% Author  : Stuart Jackson <sjackson@simpleenigma.com> [http://www.simpleenigma.com]
%%% Purpose : DNS Authoritve zone file storage
%%% Created : 2007-01-12
%%% Updated : 2007-01-12
%%%----------------------------------------------------------------------

-module(dns_catalog).

-include("dns.hrl").

-compile(export_all).



select(Domain) ->
	mnesia:wait_for_tables([dns_catalog],infinity),
	Fun = fun() -> 	
		mnesia:read({dns_catalog,Domain})
	end,
	case mnesia:sync_transaction(Fun) of
		{atomic,[]} -> [];
		{atomic,DNS_Catalog_List} -> DNS_Catalog_List
	end.
select(Domain,Type) ->
	mnesia:wait_for_tables([dns_catalog],infinity),
	Fun = fun() -> 	
		mnesia:match_object(#dns_catalog{name=Domain,type=Type,_ = '_'})
	end,
	case mnesia:sync_transaction(Fun) of
		{atomic,[]} -> [];
		{atomic,DNS_Catalog_List} -> DNS_Catalog_List
	end.


serial() -> serial(1).
serial(Version) ->
	{{Year,Month,Day},{Hour,Minute,Second}} = calendar:local_time(),
	<<D:32>> = <<Year:4,Month:2,Day:2,Hour:2,Minute:2,Second:2,0:2,Version:16>>,
	D.
	






insert(DNS_Catalog) when is_record(DNS_Catalog,dns_catalog) ->
	mnesia:wait_for_tables([dns_catalog],infinity),
	Fun = fun() -> mnesia:write(DNS_Catalog) end,
	mnesia:sync_transaction(Fun).















%%%----------------------------------------------------------------------
%%% MNESIA funcations
%%%----------------------------------------------------------------------
init()  -> mnesia:create_table(dns_catalog, [{attributes, record_info(fields, dns_catalog)}]).
drop()  -> mnesia:delete_table(dns_catalog).
clear() -> mnesia:clear_table(dns_catalof).

