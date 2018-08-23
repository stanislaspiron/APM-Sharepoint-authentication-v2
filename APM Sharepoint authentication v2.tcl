    when RULE_INIT {
         #If NTLM Auth is defined below, define the ECA_METADATA_ARG with your NTLM profile and enable eca profile in virtual server configuration with tmsh command
         # modify ltm virtual [virtual name] profile add {eca}
         set static::ECA_METADATA_ARG "select_ntlm:/Common/NTLM-Auth"
         set static::session_restore_aes_key "AES 256 affeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffeaffe"  ;# AES Key to protect and validate recovery data
         # Define required APM variables stored in the restore cookie to create new session with same security level.
         set static::session_restore_variables {
            session.ui.lang
            session.logon.last.username
            session.logon.last.logonname
            session.logon.last.krbdomain
            session.logon.last.domain
            session.krbsso.last.domain
            session.krbsso.last.username
            session.assigned.acls
            session.logon.last.domain
            session.sso.token.last.username
            session.user.sessiontype
         }
         # Cookie expire in 2 hours for the test...
         set static::session_restore_timeout 172800 ;### 7200 / 172800
      }
      
      when CLIENT_ACCEPTED {
         set last_ua_agent "init"
         # Set addtional HTTP headers in HTTP authentication responses
         set ADDITIONAL_AUTH_HEADERS "MicrosoftSharePointTeamServices 15.0.0.4763"
      }
      
      when HTTP_REQUEST {
         #################################### Authentication method selection #####################################################
         # Set authentication mode list supported. possible values are
         #   form :default Form based authentication
         #   msofba : Microsoft Office Form Based Authentication for Office and Onedrive apps
         #   persist : Add persistent cookie to recover closed session. this function is only supported by form and msofba authentications.
         #   --> persist word must be set after authentication mode : ex : {form persist} or {msofba persist}
         #   basic : Basic Authentication
         #   ntlm : NTLM Authentication
         #   negotiate : Kerberos / SPNEGO authentication : Not supported yet by this irule
         #   --> basic, ntm and negotiate can be set together. ex: {negotiate ntlm basic} {ntlm basic}
         #   deny : send a 403 response code to deny the request
         #   disable : disable APM authentication
         # Disable Authentication for Internal networks
         #if { [IP::addr [IP::client_addr]/25 equals 1.1.1.0] or [IP::addr [IP::client_addr]/25 equals 2.2.2.0] } {
         #     set AUTHENTICATION_MODE {disable}
         #     ASM::disable
         #     return
         #}
         #log local0. [HTTP::header "User-Agent"]
          if { $last_ua_agent equals [set last_ua_agent [HTTP::header value "User-Agent"]] } {
              # Do nothing, keep previous request authschema value
          } elseif {[HTTP::header exists "X-FORMS_BASED_AUTH_ACCEPTED"] && (([HTTP::header "X-FORMS_BASED_AUTH_ACCEPTED"] equals "t") || ([HTTP::header "X-FORMS_BASED_AUTH_ACCEPTED"] equals "f"))} {
              set AUTHENTICATION_MODE {msofba}
          } else {
              switch -glob -- [string tolower [HTTP::header "User-Agent"]] {
                  "*microsoft office *ios*" -
                  "*onedriveiosapp*" -
                  "onedrive/*darwin*" {
                     # NTLM is the only one supported for onedrive mobile
                     set AUTHENTICATION_MODE {ntlm basic}
                     #set AUTHENTICATION_MODE {deny}
                  }
                  "*microsoft office onedrive*" -
                  "*microsoft onedrive*" -
                  "*microsoft office skydrive*" -
                  "*microsoft office syncproc*" -
                  "*microsoft office upload center*" -
                  "*office protocol discovery*" -
                  "*microsoft office*" -
                  "*microsoft data access internet publishing provider*" -
                  "*non-browser*" -
                  "msoffice 12*" -
                  "*microsoft-webdav-miniredir*" -
                  "*ms frontpage 1[23456789]*" {
                      # Implicit MSOFBA support detected.   
                      set AUTHENTICATION_MODE {msofba}
                      #set AUTHENTICATION_MODE {ntlm basic}
                  }
                  "*ms frontpage*" {
                      # Legacy client detected
                      set AUTHENTICATION_MODE {ntlm basic}
                      #set AUTHENTICATION_MODE {deny}
                  }
                  "*mozilla*" -
                  "*opera*" {
                      # Regular web browser detected.  
                      set AUTHENTICATION_MODE {form}
                  }
                  default { 
                      set AUTHENTICATION_MODE {ntlm basic}
                      #set AUTHENTICATION_MODE {msofba}
                  }
              }
              #log local0. "[IP::remote_addr] : [string tolower [HTTP::header "User-Agent"]] : $AUTHENTICATION_MODE : [HTTP::cookie value MRHSession] : [HTTP::cookie value MRHSession_R]"
         }
         #################################### end of Authentication method selection ##############################################
      }
 
 
      priority 900
      
      when RULE_INIT {
        set static::AUTH_POLICY_FAILED                     "policy_failed"
        set static::AUTH_POLICY_SUCCEED                    "policy_succeed"
        set static::AUTH_POLICY_DONE_WAIT_SEC              5
 
        set static::AUTH_FIRST_BIG_POST_CONTENT_LEN        640000
        set static::AUTH_POLICY_RESULT_POLL_INTERVAL       100
        set static::AUTH_POLICY_RESULT_POLL_MAXRETRYCYCLE  100
        set static::AUTH_ACCESS_USERKEY_TBLNAME            "auth_access_userkey"
        set static::AUTH_ACCESS_LOG_PREFIX                 "01490000:7:"
 
        set static::AUTH_ACCESS_DEL_COOKIE_HDR_VAL         "MRHSession=deleted; \
                                                       expires=Thu, 01-Jan-1970 00:00:01 GMT;\
                                                       path=/"
 
    }
      
      when CLIENT_ACCEPTED {
         set clientless_mode 0
         set inject_session_cookie ""
         set inject_recover_cookie 0
         if { ! [ info exists ADDITIONAL_AUTH_HEADERS ] } {
            set ADDITIONAL_AUTH_HEADERS     ""
         }
      }
      
      when HTTP_REQUEST {
         set inject_session_cookie ""
         if { ! [ info exists f_ntlm_auth_succeed ] } {
            set f_ntlm_auth_succeed         0
         }
         if { ! [ info exists sid_cache ] } {
            set sid_cache                         ""
         }
        if { ! [ info exists PROFILE_POLICY_TIMEOUT ] } { 
            set PROFILE_POLICY_TIMEOUT            [PROFILE::access access_policy_timeout]
        }
        if { ! [ info exists PROFILE_MAX_SESS_TIMEOUT ] } {
            set PROFILE_MAX_SESS_TIMEOUT          [PROFILE::access max_session_timeout]
        }
         if { ! [ info exists src_ip ] } {
            set src_ip                            [IP::remote_addr]
         }
          if { ! [ info exists PROFILE_RESTRICT_SINGLE_IP ] } {
              set PROFILE_RESTRICT_SINGLE_IP        [PROFILE::access restrict_to_single_client_ip]
          }
                 
        set persisted_session_timeout       [PROFILE::access inactivity_timeout]         
        set http_method                     [HTTP::method]
        set http_uri                        [HTTP::uri]
        set http_content_len                [HTTP::header Content-Length]
        set MRHSession_cookie               [HTTP::cookie value MRHSession]
          if { ! [ info exists AUTHENTICATION_MODE ] } {
              set AUTHENTICATION_MODE {form}
          }
 
        
         switch -- [lindex $AUTHENTICATION_MODE 0] {
            "disable" {
         #################################### APM Disable #########################################################################
         # disable APM and leave irule if mode is set to disable
               ACCESS::disable
               return
            }
            "form" {
         #################################### Form based authentication ###########################################################
         # Leave irule if authentication mode is set to default form base authentication
               if {[lindex $AUTHENTICATION_MODE 1] equals "persist"} {
                  set inject_recover_cookie 1} else {set inject_recover_cookie 0}
               set apm_sessionid [HTTP::cookie value "MRHSession"]
               if {![HTTP::cookie exists MRHSession] || !($inject_recover_cookie && [HTTP::cookie exists MRHSession_R])} {return}
            }
            "deny" {
         #################################### Deny Request ########################################################################
         # Respond with 403 response code and "Access Denied" content if mode is set to deny
               HTTP::respond 403 -version "1.1" \
                  content {Access Denied.} \
                  noserver \
                  "Content-Type" "text/html" \
                  "Set-Cookie" "MRHSession=deleted;path=/;secure" \
                  "Set-Cookie" "LastMRH_Session=deleted;path=/;secure" \
                  "Set-Cookie" "MRHSession=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;secure" \
                  "Set-Cookie" "LastMRH_Session=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;secure"
               return
            }
            default {
         #################################### All other authentication methods #####################################################
         # provision response Headers for specific authentication
               set httpheaders "$ADDITIONAL_AUTH_HEADERS Set-Cookie \"MRHSession=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/\" Connection close"
               set httpcontent "ForbidenAuthentication\\ Required"
               set httpcode 401
               foreach authvalue $AUTHENTICATION_MODE {
                  switch $authvalue {
                     basic {
                        append httpheaders " WWW-Authenticate \"Basic realm=\\\"[HTTP::host]\\\"\""
                     }
                     ntlm {
                        append httpheaders " WWW-Authenticate NTLM"
                     }
                     negotiate {
                        # Authentication method negociate not managed by this irule yet
                        append httpheaders " WWW-Authenticate Negotiate"
                     }
                     msofba {
                           #log local0. [HTTP::cookie value MRHSession_SP]
                        if {[lindex $AUTHENTICATION_MODE 1] equals "persist" && [HTTP::cookie exists MRHSession_R]} {
                           set persisted_session_timeout 300
                        } elseif {[HTTP::path] ne "/vdesk/ms-ofba-form"} {
                           append httpheaders " \"Content-Type\"\ \"text/html\""
                           append httpheaders " X-FORMS_BASED_AUTH_REQUIRED"\ "https://[getfield [HTTP::host] ":" 1]/vdesk/ms-ofba-form?mode=[lindex $AUTHENTICATION_MODE 1]"
                           append httpheaders " X-FORMS_BASED_AUTH_RETURN_URL"\ "https://[getfield [HTTP::host] ":" 1]/vdesk/ms-ofba-completed"                           
                           append httpheaders " X-FORMS_BASED_AUTH_DIALOG_SIZE"\ "800x600"
                           set httpcontent "ForbidenAccess\\ Denied.\\ Make\\ sure\\ that\\ your\\ client\\ is\\ correctly\\ configured.\\ See\\ https://support.microsoft.com/en-us/kb/932118\\ for\\ further\\ information."
                           set httpcode 403
                        }
                     }
                  }
               }
            }
         }
 
         #################################### NTLM already authenticated connection ###############################################
         if {$f_ntlm_auth_succeed} {
            # enable ECA profile for already NTLM authenticated connections and ignore this irule event
            ECA::enable
            ECA::select $static::ECA_METADATA_ARG
            return
         }
         #################################### Valid session request : MHRSession Cookie ###########################################
         if { ( [set apm_sessionid [HTTP::cookie value "MRHSession"]] ne "" ) and ( [ACCESS::session exists -state_allow $apm_sessionid] ) } then {
             # Allow the successfully pre authenticated request to pass
             return
         #################################### Valid session request : MHRSession_R Cookie ########################################
         ### This cokie is inserted to allow a user to log with recorded data stored on a encrypted cookie
         } elseif {([lindex $AUTHENTICATION_MODE 0] ne "form") and ( [set apm_sessionid [HTTP::cookie value "MRHSession_SP"]] ne "" ) and ( [ACCESS::session exists -state_allow $apm_sessionid] ) } then {
         #################################### Valid session request : MHRSession_SP Cookie ########################################
            # Check if persistent APM session cookie is present and valid
            # Restore APM session cookie value
            HTTP::cookie insert name "MRHSession" value $apm_sessionid
            set inject_session_cookie $apm_sessionid 
            # Allow the successfully pre authenticated request to pass
            return
         } elseif { [lindex $AUTHENTICATION_MODE 1] equals "persist" && [HTTP::cookie exists MRHSession_R]
         and ( [set session_restore_data [AES::decrypt $static::session_restore_aes_key [b64decode [HTTP::cookie value MRHSession_R]]]]  ne "" )} {
	    array set restore_data $session_restore_data
	    if {$restore_data(timeout) > [clock seconds] } {
               set user_key "persist.[PROFILE::access name].$restore_data(session.logon.last.username)"
               if {[set apm_sessionid [table lookup -subtable  APMSessionRestore $user_key]] != "" &&  ( [ACCESS::session exists -state_allow $apm_sessionid] ) } {
                  #log local0. "session recover by table"
               } elseif { ([ llength [set cookie_list [ ACCESS::user getsid $user_key ] ] ] != 0) and [set apm_sessionid [ ACCESS::user getkey [ lindex $cookie_list 0 ] ] ] ne ""} {
                     #log local0. "session recover by cookie list"
              } else {
               #log local0. "new session"
               if { [HTTP::header value "Accept-Language"] eq "" } then {
		    # A "Accept-language" header is not present. Injecting language code = none
		    HTTP::header insert "Accept-Language" "none"
		}
		set apm_sessionid [ACCESS::session create -timeout $persisted_session_timeout]
		ACCESS::session data set -sid $apm_sessionid "session.policy.result" "allow"
		foreach session_variable [lsearch -all -inline -not -exact [array names restore_data] timeout] {
		    ACCESS::session data set -sid $apm_sessionid $session_variable $restore_data($session_variable)
		    #log local0.debug "Adding $session_variable = $restore_data($session_variable)"
		}
		ACCESS::session data set -sid $apm_sessionid ".session.assigned.uuid" "tmm.uuid.$user_key"
                ACCESS::session data set -sid $apm_sessionid "session.user.uuid" $user_key
	       }
            HTTP::cookie insert name "MRHSession" value $apm_sessionid
	    set inject_session_cookie $apm_sessionid
            table set -subtable "APMSessionRestore"  $user_key $apm_sessionid $persisted_session_timeout indef
            unset restore_data user_key
            return
         }
         }
         #################################### Request with valid Authorization Header ############################################
         ### convert authentication header to be managed by APM
          if { [ llength [set auth_data [split [HTTP::header Authorization] " "]] ] == 2 } {
               if {[lsearch -exact $AUTHENTICATION_MODE [set authvalue [string tolower [ lindex $auth_data 0]]]] ne -1} {
                  switch $authvalue {
                      "ntlm" {
                          ECA::enable
                          ECA::select $static::ECA_METADATA_ARG
                      }
                      "basic" {
                          set clientless(insert_mode) 1
                          set clientless(src_ip)      [IP::remote_addr]
                          set clientless(username)    [ string tolower [HTTP::username] ]
                          set clientless(password)    [HTTP::password]
                          if { $PROFILE_RESTRICT_SINGLE_IP == 0 } {
                              binary scan [md5 "$clientless(password)"] H* clientless(hash)
                          } else {
                              binary scan [md5 "$clientless(password)$clientless(src_ip)"] H* clientless(hash)
                          }
                          set user_key "$clientless(username).$clientless(hash)"
                          set clientless(cookie_list)             [ ACCESS::user getsid $user_key ]
                          if { [ llength $clientless(cookie_list) ] != 0 } {
                             set clientless(cookie) [ ACCESS::user getkey [ lindex $clientless(cookie_list) 0 ] ]
                             if { $clientless(cookie) != "" } {
                                HTTP::cookie insert name MRHSession value $clientless(cookie)
                                set clientless(insert_mode) 0
                             }
                         }
                         if { $clientless(insert_mode) } {
                             HTTP::header insert "clientless-mode" 1
                             HTTP::header insert "username" $clientless(username)
                             HTTP::header insert "password" $clientless(password)
                             set clientless_mode 1
                         }
                         unset clientless
                      }
                      "negotiate" {
                        #log local0.  [getfield [HTTP::header Authorization] " " 2]
                        #set clientless(insert_mode) 1
                        #set clientless(authparam) [getfield [HTTP::header Authorization] " " 2]
                        #log local0. $clientless(authparam)
                        #log local0. [string length $clientless(authparam)]
                        #set clientless(decode) [b64decode $clientless(authparam)]
                        ##log local0. [sha256 "$clientless(decode)"]
                        #binary scan [sha256 "$clientless(decode)"] H* clientless(hash)
                        #log local0. $clientless(hash)
                        #set user_key "$clientless(hash)"
                        #set clientless(cookie_list)             [ ACCESS::user getsid $user_key ]
                        #  if { [ llength $clientless(cookie_list) ] != 0 } {
                        #     set clientless(cookie) [ ACCESS::user getkey [ lindex $clientless(cookie_list) 0 ] ]
                        #     if { $clientless(cookie) != "" } {
                        #        HTTP::cookie insert name MRHSession value $clientless(cookie)
                        #        set clientless(insert_mode) 0
                        #     }
                        # }
                        #if { $clientless(insert_mode) } {
                        #     HTTP::header insert "clientless-mode" 1
                        #     set clientless_mode 1
                        # }
                        # unset clientless
                      }
                      default {
                          #other authentication methodes are not managed by this irule yet
                      }
                  }
               }
         #################################### Redirect unmanaged requests with supported authentication method  ##################               
           } else {
                eval HTTP::respond $httpcode -version 1.1 content $httpcontent noserver $httpheaders
               return
           }
      }
      
      
      when HTTP_RESPONSE {
          # Insert persistent cookie for html content type and private session
          if { [HTTP::header "Content-Type" ] contains "text/html" && [info exists "apm_sessionid"]} {
              HTTP::cookie remove MRHSession_SP
              HTTP::cookie insert name MRHSession_SP value $apm_sessionid path "/"
              HTTP::cookie expires MRHSession_SP 300 relative
              HTTP::cookie secure MRHSession_SP enable
          }
          # Insert session cookie if session was recovered from persistent cookie
          if { ([info exists "inject_session_cookie"]) && ($inject_session_cookie ne "") } {
              HTTP::cookie insert name MRHSession value $inject_session_cookie path "/"
              HTTP::cookie secure MRHSession enable
              #log local0. "injected $inject_session_cookie"
          }
         if { $inject_recover_cookie } then {
                  # Insert APM recover session cookie into HTTP response.
                  set session_restore_data "[clock seconds] [ACCESS::session data get "session.logon.last.username"]"
                  foreach session_variable $static::session_restore_variables {
                      if { [set session_variable_value [ACCESS::session data get $session_variable]] ne "" } then {
                          lappend session_restore_data "$session_variable=$session_variable_value"
                      }
                  }
                  HTTP::header insert "Set-Cookie" "MRHSession_R=[b64encode [AES::encrypt $static::session_restore_aes_key $session_restore_data]];Path=/;Secure;HttpOnly"
                  set inject_recover_cookie 0
         }
        if {[HTTP::header exists "Transfer-Encoding"]} {
            HTTP::payload rechunk
        }
      }
      
      when ACCESS_SESSION_STARTED {
          if {[set landinguri [ACCESS::session data get session.server.landinguri]] equals "/vdesk/ms-ofba-form?mode=persist" } {
            ACCESS::session data set session.server.landinguri "/vdesk/AddPersistentCookie?url=[b64encode "/vdesk/ms-ofba-completed"]"
          } elseif {([info exists "inject_recover_cookie"])} {
              ACCESS::session data set session.server.landinguri "/vdesk/AddPersistentCookie?url=[b64encode [ACCESS::session data get session.server.landinguri]]"
              ACCESS::session data set session.inactivity_timeout 300
          }
          if {([info exists "clientless_mode"])} {
              ACCESS::session data set session.clientless $clientless_mode
              if {$clientless_mode} {
               ACCESS::session data set session.inactivity_timeout 300
               if {[HTTP::header Authorization] starts_with "Negotiate"}{
                  ACCESS::session data set session.logon.last.authtype "Negotiate"         
                  ACCESS::session data set session.logon.last.authparam [getfield [HTTP::header Authorization] " " 2]
               }
              }
          }
          if { [ info exists user_key ] } {
              ACCESS::session data set "session.user.uuid" $user_key
          }
      }
      
      when ACCESS_POLICY_COMPLETED {
         if { ! [ info exists user_key ] } {
            return
        }
        
        set user_key_value ""
        set f_delete_session 0
        set policy_result [ACCESS::policy result]
        set sid [ ACCESS::session sid ]
 
        switch $policy_result {
        "allow" {
            set user_key_value          $sid
            set sid_cache               $user_key_value
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Result: Allow: $user_key"
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX sid = $sid"
 
        }
        "deny" {
            eval ACCESS::respond 401 -version 1.1 content {ForbidenAuthentication\ Required} noserver $httpheaders
            set f_delete_session  1
        }
        default {
            ACCESS::respond 503 content  $static::actsync_503_http_body Connection Close
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Got unsupported policy result for $user_key ($sid)"
            set f_delete_session  1
        }
        }
 
        if { $f_ntlm_auth_succeed == 1 } {
            if { $user_key_value != "" } {
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Setting $user_key => $static::AUTH_POLICY_SUCCEED"
                table set -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME $user_key $static::AUTH_POLICY_SUCCEED
            } else {
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Setting $user_key => $static::AUTH_POLICY_FAILED  $static::AUTH_POLICY_DONE_WAIT_SEC $static::AUTH_POLICY_DONE_WAIT_SEC in table $static::AUTH_ACCESS_USERKEY_TBLNAME"
                table set -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME $user_key $static::AUTH_POLICY_FAILED  $static::AUTH_POLICY_DONE_WAIT_SEC $static::AUTH_POLICY_DONE_WAIT_SEC
            }
        }
 
        if { $f_delete_session == 1 } {
            ACCESS::session remove
            set f_delete_session 0
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Removing the session for $user_key."
        }
      }
      
      when ACCESS_ACL_ALLOWED {
          switch -glob -- [string tolower [HTTP::path]] {
               "/vdesk/addpersistentcookie" {
                  set cookie_expire_absolute [expr {[clock seconds] + $static::session_restore_timeout}]
                  set cookie_expire_date  [clock format $cookie_expire_absolute -format "%a, %d-%b-%Y %H:%M:%S GMT" -gmt true]
                  set session_restore_data "timeout $cookie_expire_absolute"
                  foreach session_variable $static::session_restore_variables {
                      if { [set session_variable_value [ACCESS::session data get $session_variable]] ne "" } then {
                          lappend session_restore_data $session_variable $session_variable_value
                      }
                  }
                  set cookie [format "MRHSession_R=%s; path=/; expires=%s;Secure; HttpOnly" [b64encode [AES::encrypt $static::session_restore_aes_key $session_restore_data]] $cookie_expire_date]
                  ACCESS::respond 302 noserver Location [b64decode [URI::query [HTTP::uri] url]] "Set-Cookie" $cookie
               }
              "/vdesk/ms-ofba-form" {
                     ACCESS::respond 302 noserver Location "/vdesk/ms-ofba-completed"
              }
              "/vdesk/ms-ofba-completed" {
                  ACCESS::respond 200 content {
                      
                      Authenticated
                      Good Work, you are Authenticated
                      
                  } noserver
              }
              "*/signout.aspx" {
                  # Disconnect session and redirect to APM logout Page
                  ACCESS::respond 302 noserver Location "/vdesk/hangup.php3" "Set-Cookie" "MRHSession_R=deleted;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;secure"
                  event disable
                  TCP::close
                  return
              }
              "/_layouts/accessdenied.aspx" {
                  # Disconnect session and redirect to APM Logon Page
                  if {[string tolower [URI::query [HTTP::uri] loginasanotheruser]] equals "true" } {
                      ACCESS::session remove
                      ACCESS::respond 302 noserver Location "/" "Set-Cookie" "MRHSession_R=deleted;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;secure"
                      event disable
                      TCP::close
                      return
                  }
              }
              default {
                  # No Actions
              }
          }
      }
 
    when ECA_REQUEST_ALLOWED {
        set f_ntlm_auth_succeed                 1
 
        if { $MRHSession_cookie == "" } {
            # Retrieve from SID cache
            set MRHSession_cookie   $sid_cache
            HTTP::cookie insert name MRHSession value $sid_cache
        }
 
        if { $MRHSession_cookie != "" } {
            # Destroy session ID cache. This client should not need session ID cache 
            if { ($sid_cache != "") && ($sid_cache != $MRHSession_cookie) } {
                set sid_cache   ""
            }
            if { [ ACCESS::session exists -state_allow $MRHSession_cookie ] } {
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX HTTP *VALID* MRHSession cookie: $MRHSession_cookie"
                # Default profile access setting is false
                if { $PROFILE_RESTRICT_SINGLE_IP == 0 } {
                    log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Release the request"
                    return
                }
                elseif { [ IP::addr $src_ip equals [ ACCESS::session data get -sid $MRHSession_cookie "session.user.clientip" ] ] } {
                    log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX source IP matched. Release the request"
                    return
                }
                else {
                    log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX source IP does not matched"
                }
            } else {
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX HTTP *INVALID* MRHSession cookie: $MRHSession_cookie"
            }
        }
 
        set MRHSession  ""
        set sid_cache   ""
        HTTP::cookie remove MRHSession
 
        # Build user_key
        set    user_key                 {}
        append user_key                 [string tolower [ECA::username]] "@" [ string tolower [ECA::domainname] ]
        if { $PROFILE_RESTRICT_SINGLE_IP == 0 } {
            append user_key             ":" $src_ip
        }
        append user_key                 ":" [ECA::client_machine_name]
 
        set apm_cookie_list             [ ACCESS::user getsid $user_key ]
        if { [ llength $apm_cookie_list ] != 0 } {
            set MRHSession_cookie [ ACCESS::user getkey [ lindex $apm_cookie_list 0 ] ]
            if { $MRHSession_cookie != "" } {
                set sid_cache           $MRHSession_cookie
                HTTP::cookie insert name MRHSession value $MRHSession_cookie
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX APM Cookie found: $sid_cache"
                return
            }
        }
        unset apm_cookie_list
 
        set try                         1
        set start_policy_str            $src_ip
        append start_policy_str         [TCP::client_port]
 
        while { $try <=  $static::AUTH_POLICY_RESULT_POLL_MAXRETRYCYCLE } {
 
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX NO APM Cookie found"
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Trying #$try for $http_method $http_uri $http_content_len"
 
            if { $http_content_len > $static::AUTH_FIRST_BIG_POST_CONTENT_LEN } {
                # Wait at below
            } else {
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX EXEC: table set -notouch -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME -excl $user_key $start_policy_str $PROFILE_POLICY_TIMEOUT $PROFILE_MAX_SESS_TIMEOUT"
                set policy_status [table set -notouch -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME -excl $user_key $start_policy_str $PROFILE_POLICY_TIMEOUT $PROFILE_MAX_SESS_TIMEOUT]
                log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX DONE: table set -notouch -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME -excl $user_key $start_policy_str $PROFILE_POLICY_TIMEOUT $PROFILE_MAX_SESS_TIMEOUT"
                if { $policy_status == $start_policy_str } {
                    # ACCESS Policy has not started. Start one
                    HTTP::header insert "clientless-mode"    1
                    set clientless_mode 1
                    break
                } elseif { $policy_status == $static::AUTH_POLICY_SUCCEED } {
                    log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX table is out-of-sync retry"
                    table delete -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME $user_key
                    continue
                } elseif { $policy_status == $static::AUTH_POLICY_FAILED } {
                    ACCESS::disable
                    TCP::close
                    return
                }
                # Wait at below
            }
 
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Waiting  $static::AUTH_POLICY_RESULT_POLL_INTERVAL ms for $http_method $http_uri"
            # Touch the entry table
            table lookup -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME $user_key
            after  $static::AUTH_POLICY_RESULT_POLL_INTERVAL
 
            set apm_cookie_list             [ ACCESS::user getsid $user_key ]
            if { [ llength $apm_cookie_list ] != 0 } {
                set MRHSession_cookie [ ACCESS::user getkey [ lindex $apm_cookie_list 0 ] ]
                if { $MRHSession_cookie != "" } {
                    set sid_cache           $MRHSession_cookie
                    HTTP::cookie insert name MRHSession value $MRHSession_cookie
                    log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX APM Cookie found: $sid_cache"
                    return
                }
            }
 
            incr try
        }
 
        if { $try >  $static::AUTH_POLICY_RESULT_POLL_MAXRETRYCYCLE } {
            log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Policy did not finish in [ expr { $static::AUTH_POLICY_RESULT_POLL_MAXRETRYCYCLE * $static::AUTH_POLICY_RESULT_POLL_INTERVAL } ] ms. Close connection for $http_method $http_uri"
            table delete -subtable  $static::AUTH_ACCESS_USERKEY_TBLNAME $user_key
            ACCESS::disable
            TCP::close
            return
        }
 
        log -noname accesscontrol.local1.debug "$static::AUTH_ACCESS_LOG_PREFIX Releasing request $http_method $http_uri"
 
        unset try
        unset start_policy_str
    }
 
      when ECA_REQUEST_DENIED {
         log local0. "User [ECA::username]@[ECA::domainname], Client Machine [ECA::client_machine_name], Auth Status [ECA::status]"
         set f_ntlm_auth_succeed                 0
      }
