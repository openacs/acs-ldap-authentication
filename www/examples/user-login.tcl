ad_page_contract {

    Accepts an email from the user and attempts to log the user in.

    @author Multiple
    @cvs-id $Id$
} {
    email:notnull
    {return_url [ad_pvt_home]}
    password:notnull
    {persistent_cookie_p 0}
}

if ![ldap_user_exists $email] {
    # The user is not in the database. Redirect to user-new.tcl so the user can register.
    ad_set_client_property -persistent "f" register password $password
    ad_returnredirect "user-new?[ad_export_vars { email return_url persistent_cookie_p }]"

    return
}

set user_id [ldap_check_password $email $password]
if [empty_string_p $user_id] {
    # The user is in the database, but has provided an incorrect password.
    ad_returnredirect "bad-password.tcl?user_id=$user_id"
}


# The user has provided a correct, non-empty password. Log
# him/her in and redirect to return_url.
ad_user_login -forever=$persistent_cookie_p $user_id

ad_returnredirect $return_url
return
