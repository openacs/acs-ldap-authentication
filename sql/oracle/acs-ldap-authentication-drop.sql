--
-- /acs-ldap-authentication/sql/acs-ldap-authentication-drop.sql
--
-- DDL commands to purge the ACS LDAP data model
--
-- @author Dennis Gregorovic (dennis@arsdigita.com)
-- @creation-date Aug 23, 2000
-- @cvs-id $Id$
--

begin

  acs_attribute.drop_attribute ('acs_object', 'ldap_dn');

  delete from acs_object_type_tables
   where table_name = 'LDAP_ATTRIBUTES';

  commit;

end;
/
show errors
 
drop package acs_ldap;
drop table ldap_attributes;

