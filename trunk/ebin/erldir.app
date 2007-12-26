{application, erldir,
 [
  {description, "Erlang DNS/LDAP Server"},
  {vsn, "0.0.2"},
  {id, "erldir"},
  {modules,      []},
  {registered,   []},
  {applications, [kernel, stdlib, mnesia]},
  {mod, {erldir_app, []}},
  {env, [
	]}
 ]
}.








