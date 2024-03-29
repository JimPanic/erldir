%%%---------------------------------------------------------------------------------------
%%% @author     Stuart Jackson <simpleenigma@gmail.com> [http://erlsoft.org]
%%% @copyright  2006 - 2007 Simple Enigma, Inc. All Rights Reserved.
%%% @doc        ErlDir test module
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
-module(erldir_test).
-author('sjackson@simpleenigma.com').
-include("../include/dns.hrl").

-compile(export_all).

connect() -> net_adm:ping_list([dns@sfe04,dns@roark]).


q() -> dns_udp:question({10,1,1,178},53,dns_cache:get_root()).



serial() -> serial(calendar:local_time(),1).
serial({{Year,Month,Day},{Hour,Minute,Second}},Version) ->
	
	<<D:32>> = <<Year:4,Month:2,Day:2,Hour:2,Minute:2,Second:2,0:2,Version:16>>,
	D.

s() ->
	<<Year:4,Month:2,Day:2,Hour:2,Minute:2,Second:2,0:2,Version:16>> = <<4294967295:32>>,
	{{{Year,Month,Day},{Hour,Minute,Second}}, Version}.



c_insert() ->
	dns_catalog:insert(#dns_catalog{name="simpleenigma.com",type=15,class=1,ttl=86400,rdata={10,"mail.simpleenigma.com"}}),
	dns_catalog:insert(#dns_catalog{name="simpleenigma.com",type=1,class=1,ttl=86400,rdata={12,47,52,68}}),
	dns_catalog:insert(#dns_catalog{name="www.simpleenigma.com",type=1,class=1,ttl=86400,rdata={12,47,52,68}}),
	
	ok.



d() -> 
	D = dns_compress:compress(root()),
	io:format("Size: ~p~n~p~n",[size(D),D]),
	D.
c() -> 
	C = dns_compress:compress(root2()),
	io:format("Size: ~p~n~p~n",[size(C),C]),
	C.

cd() -> 
	D = dns_compress:decompress(c()),
	io:format("Size: ~p~n~p~n",[size(D),D]),
	D.

dc() -> 
	C = dns_compress:compress(d()),
	io:format("Size: ~p~n~p~n",[size(C),C]),
	C.


root() -> <<155,142,132,0,0,1,0,13,0,0,0,13,0,0,2,0,1,0,0,2,0,1,0,7,233,0,0,20,1,73,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,4,1,69,192,30,0,0,2,0,1,0,7,233,0,0,4,1,68,192,30,0,0,2,0,1,0,7,233,0,0,4,1,65,192,30,0,0,2,0,1,0,7,233,0,0,4,1,72,192,30,0,0,2,0,1,0,7,233,0,0,4,1,67,192,30,0,0,2,0,1,0,7,233,0,0,4,1,71,192,30,0,0,2,0,1,0,7,233,0,0,4,1,70,192,30,0,0,2,0,1,0,7,233,0,0,4,1,66,192,30,0,0,2,0,1,0,7,233,0,0,4,1,74,192,30,0,0,2,0,1,0,7,233,0,0,4,1,75,192,30,0,0,2,0,1,0,7,233,0,0,4,1,76,192,30,0,0,2,0,1,0,7,233,0,0,4,1,77,192,30,192,28,0,1,0,1,0,54,238,128,0,4,192,36,148,17,192,59,0,1,0,1,0,54,238,128,0,4,192,203,230,10,192,74,0,1,0,1,0,54,238,128,0,4,128,8,10,90,192,89,0,1,0,1,0,54,238,128,0,4,198,41,0,4,192,104,0,1,0,1,0,54,238,128,0,4,128,63,2,53,192,119,0,1,0,1,0,54,238,128,0,4,192,33,4,12,192,134,0,1,0,1,0,54,238,128,0,4,192,112,36,4,192,149,0,1,0,1,0,54,238,128,0,4,192,5,5,241,192,164,0,1,0,1,0,54,238,128,0,4,192,228,79,201,192,179,0,1,0,1,0,54,238,128,0,4,192,58,128,30,192,194,0,1,0,1,0,54,238,128,0,4,193,0,14,129,192,209,0,1,0,1,0,54,238,128,0,4,198,32,64,12,192,224,0,1,0,1,0,54,238,128,0,4,202,12,27,33>>.

root2() -> <<155,142,132,0,0,1,0,13,0,0,0,13,0,0,2,0,1,0,0,2,0,1,0,7,233,0,0,20,1,73,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,69,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,68,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,65,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,72,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,67,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,71,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,70,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,66,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,74,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,75,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,76,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,0,2,0,1,0,7,233,0,0,20,1,77,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,1,73,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,36,148,17,1,69,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,203,230,10,1,68,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,128,8,10,90,1,65,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,198,41,0,4,1,72,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,128,63,2,53,1,67,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,33,4,12,1,71,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,112,36,4,1,70,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,5,5,241,1,66,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,228,79,201,1,74,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,192,58,128,30,1,75,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,193,0,14,129,1,76,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,198,32,64,12,1,77,12,82,79,79,84,45,83,69,82,86,69,82,83,3,78,69,84,0,0,1,0,1,0,54,238,128,0,4,202,12,27,33>>.