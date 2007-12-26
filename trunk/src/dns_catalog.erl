%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        DNS server catalog
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
-module(dns_catalog).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").

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

