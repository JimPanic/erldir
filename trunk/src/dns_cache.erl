-module(dns_cache).

-include("dns.hrl").

-compile(export_all).





get_root() ->
	M = root_message(),
	dns_enc:encode(M).












root_message()  ->
	#message{header=root_header(),question=[root_question()]}.

root_header() -> 
	{ID,_} = random:uniform_s(65355,now()),
	root_header(ID).
root_header(ID) -> #header{id=ID,qr=0,qdcount=1}.

root_question() -> #question{qname=".",qtype=2,qclass=1}.