-- acs-ldap-authentications/sql/acs-ldap-authentication-create.sql
--
-- 
-- 
-- @author lars@pinds.com
-- @modified-by Dennis Gregorovic (dennis@arsdigita.com)
-- @creation-date created July 1, 2000
-- @cvs-id $Id$
--

create table ldap_attributes (
    object_id constraint acs_ldap_attrs_object_id_fk
              references acs_objects (object_id),
              constraint ldap_attributes_pk 
              primary key (object_id),
    dn varchar (700) not null
);

declare
 attr_id acs_attributes.attribute_id%TYPE;
begin
  insert into acs_object_type_tables
    (object_type, table_name, id_column)
  values
    ('acs_object', 'LDAP_ATTRIBUTES', 'object_id');

  attr_id := acs_attribute.create_attribute (
      object_type => 'acs_object',
      attribute_name => 'ldap_dn',
      datatype => 'string',
      pretty_name => 'LDAP Distinguished Name (dn)',
      pretty_plural => 'LDAP Distinguished Names',
      table_name => 'LDAP_ATTRIBUTES',
      column_name => 'DN',
      max_n_values => 1
  );
 commit;
end;
/
show errors

create or replace package acs_ldap
is
    function authenticate (
        url in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        password in users.password%TYPE
    )
    return integer;

    function change_password (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        password in users.password%TYPE
    )
    return integer;

    function get_attribute (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        attribute in varchar
    )
    return varchar;

    function get_dn_from_email (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        basedn in ldap_attributes.dn%TYPE,
        security_method in varchar,
        email in parties.email%TYPE
    )       
    return varchar;

    function add_user (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        first_names in persons.first_names%TYPE,
        last_name in persons.last_name%TYPE,
        email in parties.email%TYPE,
        password in users.password%TYPE
    )       
    return varchar;

end acs_ldap;
/
show errors

create or replace package body acs_ldap
is
    function Jauthenticate (
          url in varchar,
          security_method in varchar,
          dn in ldap_attributes.dn%TYPE,
          password in varchar
    ) return varchar
    as language java 
    name 'LdapLogin.authenticate(java.lang.String, java.lang.String, java.lang.String, java.lang.String) 
    returns java.lang.String';
    
    function authenticate (
        url in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        password in users.password%TYPE
    )
    return integer
    is 
        results varchar(500);
    begin
        results := Jauthenticate (url,
                                  security_method,
                                  authenticate.dn,
                                  authenticate.password);

        if results = '1' 
          then return 1;
          else return 0;
        end if;
    end authenticate;

    function Jchange_password (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        password in varchar
    ) return varchar
    as language java 
    name 'LdapLogin.change_password(java.lang.String, java.lang.String, java.lang.String, 
                                    java.lang.String, java.lang.String, java.lang.String) 
    returns java.lang.String';
    
    function change_password (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        password in users.password%TYPE
    )
    return integer
    is 
        results varchar(500);
    begin
        results := Jchange_password (url,
                                     rootdn,
                                     rootpw,
                                     security_method,
                                     change_password.dn,
                                     change_password.password);
        if results = '1' 
          then return 1;
          else return 0;
        end if;
    end change_password;

    function Jget_attribute (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        attribute in varchar
    ) return varchar
    as language java 
    name 'LdapLogin.get_attribute(java.lang.String, java.lang.String, java.lang.String, 
                                  java.lang.String, java.lang.String, java.lang.String) 
    returns java.lang.String';
    
    function get_attribute (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        attribute in varchar
    )
    return varchar
    is 
        results varchar(500);
    begin
        results := Jget_attribute (url,
                                   rootdn,
                                   rootpw,
                                   security_method,
                                   dn,
                                   attribute);
        return results;
    end get_attribute;

    function Jget_dn_from_email (
          url in varchar,
          rootdn in ldap_attributes.dn%TYPE,
          rootpw in varchar,
          basedn in ldap_attributes.dn%TYPE,
          security_method in varchar,
          email in varchar
    ) return varchar
    as language java 
    name 'LdapLogin.get_dn_from_email(java.lang.String, java.lang.String, java.lang.String, 
                                      java.lang.String, java.lang.String, java.lang.String) 
    returns java.lang.String';

    function get_dn_from_email (
          url in varchar,
          rootdn in ldap_attributes.dn%TYPE,
          rootpw in varchar,
          basedn in ldap_attributes.dn%TYPE,
          security_method in varchar,
          email in parties.email%TYPE
    )
    return varchar 
    is
        results ldap_attributes.dn%TYPE;
    begin
        results := Jget_dn_from_email (url,
                                       rootdn,
                                       rootpw,
                                       basedn,
                                       security_method,
                                       email);
        return results;
    end;

    function Jadd_user (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        first_names in persons.first_names%TYPE,
        last_name in persons.last_name%TYPE,
        email in parties.email%TYPE,
        password in users.password%TYPE
    ) return varchar
    as language java 
    name 'LdapLogin.add_user(java.lang.String, java.lang.String, java.lang.String, java.lang.String, 
                             java.lang.String, java.lang.String, java.lang.String, java.lang.String, 
                             java.lang.String) 
    returns java.lang.String';

    function add_user (
        url in varchar,
        rootdn in ldap_attributes.dn%TYPE,
        rootpw in varchar,
        security_method in varchar,
        dn in ldap_attributes.dn%TYPE,
        first_names in persons.first_names%TYPE,
        last_name in persons.last_name%TYPE,
        email in parties.email%TYPE,
        password in users.password%TYPE
    )
    return varchar 
    is
        results ldap_attributes.dn%TYPE;
    begin
        results := Jadd_user (url,
                              rootdn,
                              rootpw,
                              security_method,
                              dn,
                              first_names,
                              last_name,
                              email,
                              password);
        return results;
    end;

end acs_ldap;
/
show errors
