# /packages/acs-ldap-authentication/tcl/ldap-procs.tcl
ad_library {

    Provides methods for authenticating a user-logon via LDAP.

    @creation-date 23 Jun 2000
    @author Dennis Gregorovic [dennis@arsdigita.com]
    @author Lars Pind [lars@pinds.com]
    @cvs-id $Id$
}

# The following two are temporary
ad_proc default_parameter_value {
    parameter_name package_key 
} {
    return [db_string parameter_value {
        select default_value
          from apm_parameters
         where package_key = :package_key
           and parameter_name = :parameter_name
    } ]
}

ad_proc set_default_parameter_value {
    parameter_name package_key default_value
} {
    db_dml set_parameter_value {
        update apm_parameters
           set default_value = :default_value
         where package_key = :package_key
           and parameter_name = :parameter_name
    }
}

ad_proc -public ldap_user_exists { email } {
    Checks to see if a user with the given email address exists in either the local 
    database or on the LDAP server.  Returns 1 if the user exists, 0 otherwise.
} {
    # check to see if the user is in the local cc_users table
    set user_id [cc_email_user $email]
    if ![empty_string_p $user_id] {
        # user is in local database
        return 1
    }
    # check the LDAP server
    set dn [ldap_get_dn_from_email $email]
    if ![empty_string_p $dn] {
        # user is on LDAP server
        return 1
    }
    return 0
}

ad_proc -public ldap_get_dn_from_email { email } {
    Queries the LDAP server for an entry with given email address.  If it finds
    exactly one entry that matches, then it returns the DN of that entry.  Otherwise
    it returns the empty string.
} {
    ns_log debug "ldap_get_dn_from_email: $email"

    # Set the LDAP environment variables
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method

    set dn [db_exec_plsql get_dn_from_email {
        begin
        :1 := acs_ldap.get_dn_from_email(
            url => :url, 
            rootdn => :rootdn, 
            rootpw => :rootpw, 
            basedn => :basedn, 
            security_method => :security_method, 
            email => :email);
        end;
    }]
    
    if ![ldap_valid_value_p $dn] {
        # There was a problem with the query
        ns_log Notice "ldap_get_dn_from_email: invalid value $dn"
        return ""
    }

    # Relative DNs are returned from the LDAP call.  If a basedn is
    # supplied, append it now to set the full DN.
    if ![empty_string_p $basedn] {
        set dn "$dn, $basedn"
    } 

    return $dn
}

ad_proc -public ldap_check_password { email password_from_form } { 
    Returns the user's user_id if the password is correct for the given email. 
    Returns the empty_string otherwise.  If the password is correct, it also updates
    the user's local information from the LDAP server.
} {
    # Set the LDAP environment variables
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method

    # Get the dn for the password
    set dn [ldap_get_dn_from_email $email]

    if [empty_string_p $dn] {
        # No user with the email address given is on the LDAP server
        return ""
    }

    # Hash the password
    #set password [ns_sha1 "$password_from_form"]
    set password $password_from_form

    # Verify the hashed password
    if ![db_exec_plsql password_validate {
        begin
        :1 := acs_ldap.authenticate (
            url => :url, 
            security_method => :security_method, 
            dn => :dn, 
            password => :password);
        end;
    }] {
        return ""
    }

    # check to see if the user is in the local cc_users table
    set user_id [cc_email_user $email]
    if [empty_string_p $user_id] {
        # insert user into local database
        set user_id [ldap_add_user_from_dn $dn]

        if !$user_id {
            return ""
        }
    } else {
        # Keep local user info in sync
        ldap_sync_user_from_dn $dn
    }

    # Keep local password in sync
    ad_change_password $user_id $password_from_form

    return $user_id
}

ad_proc -public ldap_change_password { dn password_from_form } { 
    Change the user's password on the LDAP server.  Return 1 if successful,
    0 otherwise.
} {
    ns_log debug "LDAP_CHANGE_PASSWORD $dn"

    # Set the LDAP environment variables
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method

    # Hash the password
    #set password [ns_sha1 "$password_from_form"]
    set password $password_from_form

    if ![db_exec_plsql password_update {
        begin
        :1 := acs_ldap.change_password (
            url => :url, 
            rootdn => :rootdn, 
            rootpw => :rootpw, 
            security_method => :security_method, 
            dn => :dn, 
            password => :password);
        end;
    } ] {
        return 0 
    }

    set user_id [db_string user_id_select {
        select object_id
          from ldap_attributes
         where dn = :dn
    } -default ""]

    if ![empty_string_p $user_id] {
        # Keep local password in sync
        ad_change_password $user_id $password_from_form
    }

    return 1
}

ad_proc -public ldap_user_new { 
    { -dn "" }
    email first_names last_name password password_question password_answer  
    {url ""} {email_verified_p "t"} {member_state "approved"} {user_id ""} 
} {
    Creates a new user locally.  Then associates this user with the
    given dn if one is supplied or with a newly created dn otherwise.  
    Returns the user_id upon success or the empty_string upon failure.
} {
    ns_log debug "LDAP_USER_NEW $dn $email $first_names $last_name"

    set user_id [ad_user_new $email $first_names $last_name \
            $password $password_question $password_answer $url \
            $email_verified_p $member_state $user_id]

    if !$user_id { 
        # We could not create the user locally so exit.
        return "" 
    }

    if [empty_string_p $dn] {
        # No dn was supplied so we need to create one
        set dn [ldap_make_dn $user_id]
    }

    if ![ldap_add_object $user_id $dn] { 
        # We could not associate the dn with the user 
        return 0 
    }

    return $user_id
}

ad_proc ldap_add_user_to_server { dn first_names last_name email password } {
    Add an entry to the LDAP server for the given dn and populate it with 
    the infor from the other arguments.  Return 1 upon success or 0 otherwise.
} {
    ns_log debug "LDAP_ADD_USER_TO_SERVER $dn $first_names $last_name $email $password"

    # Set the LDAP environment variables
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method

    set dn [db_exec_plsql user_add {
        begin
        :1 := acs_ldap.add_user (
            url => :url, 
            rootdn => :rootdn, 
            rootpw => :rootpw, 
            security_method => :security_method, 
            dn => :dn, 
            first_names => :first_names, 
            last_name => :last_name, 
            email => :email, 
            password => :password);
        end;
    } ]

    if ![ldap_valid_and_not_empty_p $dn] {
        ns_log Error "LDAP (add_user_to_server): $dn"
        return 0
    }

    return 1
}

ad_proc -private ldap_sync_user_from_dn { dn } {
    Looks up information for user with specified dn in the LDAP server.  Then updates
    the user's local data with this information.  This only works if the user already
    is in the local database.  Return 1 upon success, 0 otherwise.
} {
    ns_log debug "LDAP_SYNC_USER_FROM_DN $dn"

    set first_names [ldap_get_attribute $dn "givenName"]
    set last_name [ldap_get_attribute $dn "sn"]
    set email [ldap_get_attribute $dn "mail"]

    if { [ldap_valid_and_not_empty_p $first_names] && \
            [ldap_valid_and_not_empty_p $last_name] && \
            [ldap_valid_and_not_empty_p $email] } {
        db_transaction {
            ns_log debug "updating $dn.  first_names: $first_names, last_name: $last_name, email: $email"
            if [catch {
                db_dml party_info_update {
                    update parties
                       set email = :email
                     where party_id = (select object_id 
                                         from ldap_attributes
                                        where dn = :dn)
                }
                db_dml person_info_update {
                    update persons
                       set first_names = :first_names,
                           last_name = :last_name
                     where person_id = (select object_id 
                                         from ldap_attributes
                                        where dn = :dn)
                }
            } errmsg] {
                # Problem updating the user info
                ns_log Error "LDAP (sync_user_from_dn): $errmsg"
                return 0
            }
        }
    } else {
        # There was a problem fetching at least one of the user attributes
        return 0
    }

    return 1
}

ad_proc -private ldap_add_user_from_dn { dn } {
    Looks up information for user with specified dn in the LDAP server.  Then create a
    new local user with this info.
} {
    ns_log debug "LDAP_ADD_USER_FROM_DN $dn"

    set first_names [ldap_get_attribute $dn "givenName"]
    set last_name [ldap_get_attribute $dn "sn"]
    set email [ldap_get_attribute $dn "mail"]

    if { [ldap_valid_and_not_empty_p $first_names] && \
            [ldap_valid_and_not_empty_p $last_name] && \
            [ldap_valid_and_not_empty_p $email] } {
        return [ldap_user_new -dn $dn $email $first_names $last_name "" "" ""]
    } else {
        ns_log Error "LDAP: Could not add user for $dn: $first_names, $last_name, $email"
        return 0
    }
}

ad_proc -public ldap_get_attribute { dn attribute } {
    Queries the LDAP server for the value of the given attribute  in the entry designated 
    by the DN.
} {
    # Set the LDAP environment variables
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method

    return [db_exec_plsql attribute_fetch {
        begin
        :1 := acs_ldap.get_attribute (
                   url => :url, 
                   rootdn => :rootdn, 
                   rootpw => :rootpw, 
                   security_method => :security_method, 
                   dn => :dn, 
                   attribute => :attribute);
        end;
    }]
}
        
ad_proc -private ldap_set_environment {} {
    A convenience function for setting up common local variables from LDAP Package paramter
    values.
} {
    set url             [default_parameter_value LdapUrl acs-ldap-authentication]
    set rootdn          [default_parameter_value LdapRootDn acs-ldap-authentication]
    set rootpw          [default_parameter_value LdapRootPw acs-ldap-authentication]
    set basedn          [default_parameter_value LdapBaseDn acs-ldap-authentication]
    set security_method [default_parameter_value LdapSecurityMethod acs-ldap-authentication]

    return [list $url $rootdn $rootpw $basedn $security_method]
}

ad_proc -private ldap_add_object { object_id dn } {
} {
    ns_log debug "LDAP_ADD_OBJECT $object_id $dn"
    if [catch {
        db_dml insert_ldap_attribute {
            insert into ldap_attributes
              (object_id, dn)
            values
              (:object_id, :dn)
        }
    } errmsg] {
        ns_log warning "ldap_set_environment: Failed on insert into ldap_attributes for object $object_id with dn $dn: $errmsg"
        return 0
    }
    
    return 1
}

ad_proc -private ldap_valid_value_p { value } {
    Checks that the value is not an LDAP error string
} {
    return [expr [string first "__LDAP_ERROR" $value] != 0]
}

ad_proc -private ldap_valid_and_not_empty_p { value } {
    Checks that the value is not empty or an LDAP error string
} {
    return [expr ![empty_string_p $value] && [ldap_valid_value_p $value]]
}

ad_proc -private ldap_make_dn { object_id } {
    Creates a unique dn based on the object_id
} {
    util_unlist [ldap_set_environment] url rootdn rootpw basedn security_method
    set dn "uid=$object_id [ns_info hostname] [ns_time], $basedn"
}
