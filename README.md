liteauth
========

LiteStack authentication middlewares

## Swauth integrated API

# Config

	[filter:liteauth-token]
	use = egg:liteauth#liteauth_token
	
	[filter:lite-swauth]
	use = egg:liteauth#liteswauth
	whitelist_url = /v1/liteauth/whitelist
	invite_url = /v1/liteauth/invites
	super_admin_key = <swauth super admin key>
	
	[filter:oauth-login-g]
	use = egg:liteauth#oauthlogin
	oauth_provider = google_oauth
	# google_oauth params
	google_client_id = <client id>
	google_client_secret = <client secret>
	google_scope = https://www.googleapis.com/auth/userinfo.profile,https://www.googleapis.com/auth/userinfo.email
	# login_oauth params
	auth_endpoint = https://<auth proxy server address>/login/g
	service_domain = https://<main proxy server address>
	
	[filter:oauth-login-fb]
	use = egg:liteauth#oauthlogin
	oauth_provider = facebook_oauth
	# facebook_oauth params
	facebook_client_id = <client id>
	facebook_client_secret = <client secret>
	facebook_scope = basic_info,email
	# login_oauth params
	auth_endpoint = https://<auth proxy server address>/login/f
	service_domain = https://<main proxy server address>
	
	[pipeline:main]
	pipeline = <...> cache liteauth-token oauth-login-g oauth-login-fb lite-swauth swauth <...> proxy-server

Take note of the following config options, will be used in API calls:

 - auth_endpoint
 - service_domain

# API calls

Example strings:

auth_endpoint = https://auth.example.com/login/fb
service_domain = https://www.example.com

----

Login call

----

Request: `GET <auth_endpoint>?state=<my_path>`

Response: `302 Redirect` -> will redirect user to the provider Oauth2 flow

Redirect End: User will be returned to: `<service_domain><my_path>?account=<account_id>:<user_id>`

Example:

Request: `GET https://auth.example.com/login/fb?state=/ui`

Response: `302 Redirect` -> will redirect user to the provider Oauth2 flow

Redirect End: User will be returned to: `https://www.example.com/ui?account=fb_1111111:me@example.com`

----

After redirect is ended two cookies will be set in the browser:

1. Name: `session`, Value: `<auth token>`, Path: `/`, Domain: `<auth_endpoint_domain>`, Secure, HttpOnly.
2. Name: `storage`, Value: `<auth_endpoint>`, Path: `/`, Domain: `<auth_endpoint_domain>`, Secure

You can retrieve `storage` cookie with Javascript, you cannot retreive `session` cookie, by design.

----

Get Profile call

----

Request: `GET <auth_endpoint_domain>/profile`

Responses:

  - `200` -> user is ok, you will get back a json document with the following format:

	{
	  "groups": [
	    { "name": "<user_account_id>:<user_name>" },
             { "name": "<user_account_id>" },
             { "name": ".admin"}
           ],
           "auth": "plaintext:<user_authorization_key>"
	}

  - `401` -> user is unathorized for the operation (cookies expired?), `prompt to re-login`.
  - `404` -> user never logged in before, call `Update Profile`.
  - `402` -> user is not in whitelist, prompt user to enter `invite token`, otherwise - access denied.
  - `409` -> user account was created with different auth provider (ex. created with Google, and user is logged in with Facebook), `prompt to re-login`.

Example:

Request: `GET https://auth.example.com/profile`

Response: 

    {
      "groups": [
        { "name": "g_11111111:me@example.com" },
        { "name": "g_11111111" },
        { "name": ".admin"}
      ],
      "auth": "plaintext:aaaa-bbbb-cccc-dddd"
    }

----

Update Profile call

----

Request: `PUT <auth_endpoint_domain>/profile`

Optional headers:

  - `X-Auth-User-Key`: `string` - user can set `<user_authorization_key>` here, or get a random one (if unset).
  - `X-Auth-Invite-Code`: `string` - user can send an `invite token` here, if has one.

Responses:

  - `201` -> profile was created, proceed to `Get Profile` call.
  - `202` -> same as above.
  - `401` -> user is unathorized for the operation (cookies expired?), `prompt to re-login`.
  - `403` -> user is forbidden for the operation, access denied, may try to re-login.
  - `500` -> internal server error, may try to re-login.

Example:

Request: `PUT https://auth.example.com/profile`

Headers: 

`X-Auth-User-Key: my_secret_password!!!1111`

`X-Auth-Invite-Code: 1111-1111-1111`

Response: `201 Created`

----

At this stage you should have all the user data needed to login through Swauth.

Tenant-Id: `<user_account_id>`  
User-Name: `<user_name>`  
Auth-Key: `<user_authorization_key>`

Go ahead and login using http://gholt.github.io/swauth/dev/api.html

----

After you log in to Swauth successfully two cookies will be set in the browser:

1. Name: `session`, Value: `<swauth token>`, Path: `/`, Domain: `<service_domain>`, Secure, HttpOnly.
2. Name: `storage`, Value: `<swauth_swift_endpoint>`, Path: `/`, Domain: `<service_domain>`, Secure

You can retrieve `storage` cookie with Javascript, you cannot retreive `session` cookie, by design.

Now you can retrieve `storage` cookie anytime user reloads the whole page, and have the endpoint handy for requests.

Example:

`storage=https://www.example.com/v1/AUTH_2222-3333-4444-55555555`

