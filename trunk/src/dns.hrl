-define(TYPE_A,1).      % host address
-define(TYPE_NS,2).     % Authoritive Name Server 
-define(TYPE_MD,3).     % Mail Destination (Obsolete)
-define(TYPE_MF,4).     % Mail Forwarder (Obsolete)
-define(TYPE_CNAME,5).  % Canonical Name for an Alias
-define(TYPE_SOA,6).    % Start of Authority
-define(TYPE_MB,7).     % Mailbox Domain Name (Experimental)
-define(TYPE_MG,8).     % Mail Group Member (Experimental)
-define(TYPE_MR,9).     % Mail Rename Domain Name (Experimental)
-define(TYPE_NULL,10).  % NULL RR (Experimental)
-define(TYPE_WKS,11).   % Well Known Service Description
-define(TYPE_PTR,12).   % Domain Name Pointer
-define(TYPE_HINFO,13). % Host Information
-define(TYPE_MINFO,14). % mailbox or mail list information
-define(TYPE_MX,15).    % Mail eXchange
-define(TYPE_TXT,16).   % Text Strings

-define(A_ROOT_SERVERS_NET,{198,41,0,4}).

-define(QTYPE_AXFR,252).     % Request a zone transfer
-define(QTYPE_MAILB,253).    % Request mailbox-related records (MB, MR or MR)
-define(QTYPE_MAILA,254).    % Request Mail Agent RR (Obsolete)
-define(QTYPE_WILDCARD,255). % Request All Records


-define(CLASS_IN,1). % Internet
-define(CLASS_CS,2). % CSNET (Obsolete)
-define(CLASS_CH,3). % CHAOS
-define(CLASS_HS,4). % Hesiod [Dyer 87]

-define(QCLASS_WILDCARD,255). % Any Class


-record(dnsd,{
	address = [],
	port    = [],
	packet  = [],
	message = []
	}).

-record(dnsd_conn,{
	acceptor = [],
	listen = [],
	port = [],
	type = [], % tcp or udp
	pid = []
	}).



-record(message,{
	header     = [],
	question   = [],
	answer     = [],
	authority  = [],
	additional = []
	}).

-record(header,{
	id      = 0, % 16 bit ID
	qr      = 0, % Query = 0, Response = 1
	opcode  = 0, % QUERY = 0, IQUERY =1, STATUS = 2
	aa      = 0, % Authoritive Answer
	tc      = 0, % TrunCation
	rd      = 0, % Recursion Desired
	ra      = 0, % Recursion Available
	z       = 0, % Reserved for Future use
	rcode   = 0, % Response Code
	qdcount = 0, % 16 bit int question count
	ancount = 0, % 16 bit in answer count
	nscount = 0, % 16 bit int name server count in auth record section
	arcount = 0  % 16 bit int additional record count
	}).

-record(question,{
	qname  = [], % Domain Name in label form
	qtype  = 0,  % two octet code for type of query
	qclass = 0   % two octet code for type of class
	}).

-record(dns_catalog,{
	name   = [], % Domain Name String
	type   = 0,  % two octet type code
	class  = 0,  % two octet class code
	ttl    = 86400,  % Time To Live
	expire = 0,  % Expiration time in seconds from UNIX EPOCH
	rdata  = []  % variable term (based on type) that describes the resource
	}).

-record(dns_cache,{
	name   = [], % Domain Name String
	type   = 0,  % two octet type code
	class  = 0,  % two octet class code
	ttl    = 86400,  % Time To Live
	expire = 0,  % Expiration time in seconds from UNIX EPOCH
	rdata  = []  % variable term (based on type) that describes the resource
	}).

-record(rr,{
	name     = [],   % Domain Name String
	type     = 0,    % two octet type code
	class    = 0,    % two octet class code
	ttl      = 86400, % Time To Live
	rdlength = 0,    % Length of RDATA field
	rdata    = []    % variable term (based on type) that describes the resource
	}).

-record(soa,{
	mname   = [],
	rname   = [],
	serial  = 0,
	refresh = 0,
	retry   = 0,
	expire  = 0,
	minimum = 0
	}).



