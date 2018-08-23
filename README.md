# Description

**This new version of irule supports NTLM auth (mandatory for Onedrive Apps)**

APM is a great authentication service but it does it only with forms.

The default behavior is to redirect user to /my.policy to process VPE. this redirect is only supported for GET method.

Sharepoint provide 3 different access types:

browsing web site with a browser

*   Editing documents with Office
*   connect to One Drive on premise from PC and mobiles
*   browser folder with webdav client (or editing documents with libreoffice through webdav protocol)

This irule display best authentication method for each of these access types:

*   browsers authenticate with default authentication method (form based authentication)
*   Microsoft office authenticate with Form based authentication (with support of MS-OFBA protocol)
*   Libreoffice and webdav clients authenticate with 401 basic authentication (NTLM and Basic)
*   Form based authentication (browser and Microsoft office) is compatible (validated for one customer) with SAML authentication
*   NTLM auth for Onedrive mobile applications

Editing documents is managed with a persistent cookie expiring after 5 minutes. to be shared between IE and Office, it requires :

*   cookie is persistent (expiration date instead of deleted at the end of session)
*   web site defined as "trusted sites" in IE.

# How to use : 
install this irule and enable it on the VS.

In the first HTTP_REQUEST event, configure authentication mode list by setting the AUTHENTICATION_MODE variable

Set authentication mode list supported. possible values are :

*   form :default Form based authentication
*   msofba : Microsoft Office Form Based Authentication for Office and Onedrive apps
*   persist : Add persistent cookie to recover closed session. this function is only supported by form and msofba authentications.

    *   --> persist word must be set after authentication mode : ex : {form persist} or {msofba persist}

*   basic : Basic Authentication

*   ntlm : NTLM Authentication

*   negotiate : Kerberos / SPNEGO authentication : Not supported yet by this irule

    *   --> basic, ntm and negotiate can be set together. ex: {negotiate ntlm basic} {ntlm basic}

*   deny : send a 403 response code to deny the request

*   disable : disable APM authentication
