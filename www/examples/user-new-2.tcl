# /www/register/user-new-2.tcl

ad_page_contract {
    Enters a new user into the database.
    @cvs-id  $Id$
} {
    { email }
    { password }
    { password_confirmation }
    { first_names:notnull }
    { last_name:notnull }
    { question }
    { answer }
    { url }
    { user_id:integer,notnull }
    { return_url [ad_pvt_home] }
    { persistent_cookie_p 0 }
} -properties {
    header:onevalue
    footer:onevalue
    email_verified_p:onevalue
    email:onevalue
    site_link:onevalue    
}

# xxx: Need an equivalent to ad_handle_spammers.

set exception_count 0
set exception_text ""

if {[info exists first_names] && [string first "<" $first_names] != -1} {
    incr exception_count
    append exception_text "<li> You can't have a &lt; in your first name because it will look like an HTML tag and confuse other users."
}

if {[info exists last_name] && [string first "<" $last_name] != -1} {
    incr exception_count
    append exception_text "<li> You can't have a &lt; in your last name because it will look like an HTML tag and confuse other users."
}

if { [info exists url] && [string compare $url "http://"] == 0 } {
    # the user left the default hint for the url
    set url ""
} elseif { ![util_url_valid_p $url] } {
    # there is a URL but it doesn't match our REGEXP
    incr exception_count
    append exception_text "<li>You URL doesn't have the correct form.  A valid URL would be something like \"http://photo.net/philg/\"."
}

if {[parameter::get -parameter RegistrationProvidesRandomPasswordP -default 0]} {
    set password [ad_generate_random_string]
} elseif { ![info exists password] || [empty_string_p $password] } {
    incr exception_count
    append exception_text "<li>You haven't provided a password.\n"
} elseif { [string compare $password $password_confirmation] } {
    incr exception_count
    append exception_text "<li>The passwords you've entered don't match.\n"
}

set member_state "approved"
set email_verified_p "t"

# We've checked everything.
# If we have an error, return error page, otherwise, do the insert

if {$exception_count > 0} {
    ad_return_complaint $exception_count $exception_text
    ad_script_abort
}

set double_click_p 0

if { [db_string user_exists "select count(*) from registered_users where user_id = :user_id"] } {
    set double_click_p 1
} else {
    set dn [ldap_make_dn $user_id]
    set result [ldap_add_user_to_server $dn $first_names $last_name $email $password]
    if [empty_string_p $result] {
        ad_return_error "User Creation Failed" "We were unable to create your user record in the ldap database."
        ad_script_abort
    }
    set user_id [ldap_user_new -dn $dn $email $first_names $last_name $password $question \
            $answer $url $email_verified_p $member_state $user_id]
    if { !$user_id } {
	ad_return_error "User Creation Failed" "We were unable to create your user record in the database."
        ad_script_abort
    }
}

if { [ad_check_password $user_id $password] } {
    # Log the user in.
    ad_user_login -forever=$persistent_cookie_p $user_id
}

ad_returnredirect $return_url
