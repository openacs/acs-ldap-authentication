set startclicks [clock clicks]

ReturnHeaders text/plain

ns_write "
ldap_set_environment: [ldap_set_environment]
[expr ($startclicks - [clock clicks]) / 1000]:
"

util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method
set dn "cn=Joe User, $basedn"
set first_names "Joe"
set last_name "User"
set mail "foo@bar.com"
set password "dennis"

set dn [db_exec_plsql add_user {
    begin
    :1 := acs_ldap.add_user (:url, :rootdn, :rootpw, :security_method, :dn, :first_names, :last_name, :mail, :password);
    end;
} ]
ns_write $dn

ns_write "
ldap_user_exists: [ldap_user_exists foo@bar.com]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 1

ns_write "
ldap_user_exists: [ldap_user_exists fool@bar.com]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 0

ns_write "
get_dn_from_email: [ldap_get_dn_from_email foo@bar.com]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return cn=Joe User, $basedn

ns_write "
get_dn_from_email: [ldap_get_dn_from_email fool@bar.com]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return ""

ns_write "
ldap_change_password: [ldap_change_password [ldap_get_dn_from_email foo@bar.com] dennis1]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 1

ns_write "
ldap_check_password: [ldap_check_password foo@bar.com dennis]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 0

ns_write "
ldap_check_password: [ldap_check_password fool@bar.com dennis]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 0

ns_write "
ldap_check_password: [ldap_check_password foo@bar.com dennis1]
[expr ($startclicks - [clock clicks]) / 1000]: "
#should return 1









