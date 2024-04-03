# NEMO ID document

This document describes **NEMO ID**'s OAuth 2.0 implementation for authentication, which conforms to the [OpenID Connect](https://openid.net/connect/) specification.

[Identity, Authentication + OAuth = OpenID Connect](http://www.youtube.com/watch?feature=player_embedded&v=Kb56GzQ2pSk)

Read this content in other languages: [English](README.md), [Tiếng Việt](README.vi.md)


## Setting up

Before your application can use **NEMO ID**'s OAuth 2.0 authentication system for user login, you must register the application with **NEMO ID**'s admin to obtain OAuth 2.0 credentials, set a redirect URI, and (optionally) customize the branding information that your users see on the login and user-consent screen.

![](/public/images/login-consent.png)

**_Example of settings:_**

_\* Italic text values vary depending on the application_

<table>
  <tr>
    <th colspan="2">Issuer</th>
  </tr>
  <tr>
    <td>Issuer</td>
    <td><i>https://gid.nemoverse.io</i></td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">Redirect URIs</th>
  </tr>
  <tr>
    <td>Redirect URI</td>
    <td><i>https://wallet.nemoverse.io/callback, nemo.app.wallet.android:/callback, nemo.app.wallet.ios:/callback, http://127.0.0.1</i></td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">Customize branding</th>
  </tr>
  <tr>
    <td>App name</td>
    <td><i>Nemo Wallet</i></td>
  </tr>
  <tr>
    <td>Logo</td>
    <td><i>(Send a image file to admin)</i></td>
  </tr>
  <tr>
    <td>Application home page</td>
    <td><i>https://nemoverse.io</i></td>
  </tr>
  <tr>
    <td>Application privacy policy</td>
    <td><i>https://galixcity.io/privacy-policy</i></td>
  </tr>
  <tr>
    <td>Application terms of service</td>
    <td><i>https://galixcity.io/terms-of-use</i></td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">Credential (Admin will provide after successful client registration)</th>
  </tr>
  <tr>
    <td>Client ID</td>
    <td><i>c72fa486-93f3-4d10-a558-93e878e6e14b.nemoverse</i></td>
  </tr>
  <tr>
    <td>Client secret</td>
    <td><i>64bca355-61f8-40d5-b495-550048ebbcb5</i></td>
  </tr>
</table>


## Accessing the service

**NEMO ID** provide libraries that you can use to take care of many of the implementation details of authenticating users.

> **Note:**  Given the security implications of getting the implementation correct, we strongly encourage you to take advantage of a pre-written library or service. Authenticating users properly is important to their and your safety and security, and using well-debugged code written by others is generally a best practice. For more information, see [Client libraries](#client-libraries).

If you **choose not to use a library**, follow the instructions in the remainder of this document, which describes the HTTP request flows that underly the available libraries.


## Authenticating the user

Authenticating the user involves obtaining an ID token and validating it. [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) are a standardized feature of [OpenID Connect](https://openid.net/connect/) designed for use in sharing identity assertions on the Internet.

The most commonly used approaches for authenticating a user and obtaining an ID token are called the "Authorization code" flow and the "Implicit" flow.

- **Authorization code flow** -- this flow is the most commonly used, for traditional web apps as well as native/mobile apps.\
  Start with a browser redirect to / from the OP for user authentication and consent, then send a back-channel request to retrieve the token ID.\
  This flow provides optimal security, as tokens are not revealed to the browser and the client can also be authenticated.

- **Implicit flow** -- for browser-based (JavaScript) apps without a backend.\
  The token ID is received directly with the redirect response from the OP. No back-channel request required.

This document describes how to perform the "Authorization code" flow (with PKCE) for authenticating the user. The implicit flow is significantly more complicated because of security risks in handling and using tokens on the client side (front-end).

### Authorization code flow With Proof Key of Code Exchange (PKCE)

PKCE ([RFC 7636](http://tools.ietf.org/html/rfc7636)) is an extension of Authorization Code flow to prevent CSRF and authorization code injection attacks. **NEMO ID** uses Authorization Code flow with PKCE for safety and security purposes.

![](/public//images/auth-code-pkce-flow.png)

_Authorization Code flow with PKCE_

Make sure you [set up your app](#setting-up) to enable it to use these protocols and authenticate your users. When a user tries to log in with **NEMO ID**, you need to:

1. [Create an anti-forgery state token, nonce, code verifier and code challenge](#1-create-an-anti-forgery-state-token-nonce-code-verifier-and-code-challenge)

2. [Send an authentication request to **NEMO ID**](#2-send-an-authentication-request-to-nemo-id)

3. [Confirm the anti-forgery state token](#3-confirm-the-anti-forgery-state-token)

4. [Exchange `code` for access token and ID token](#4-exchange-code-for-access-token-and-id-token)

5. [Obtain user information from the ID token](#5-obtain-user-information-from-the-id-token)

6. [Authenticate the user](#6-authenticate-the-user)

#### 1. Create an anti-forgery state token, nonce, code verifier and code challenge

You must protect the security of your users by preventing request forgery attacks. The first step is creating a unique session token that holds state between your app and the user's client. You later match this unique session token with the authentication response returned by **NEMO ID** to verify that the user is making the request and not a malicious attacker. These tokens are often referred to as cross-site request forgery (CSRF) tokens.

To minimize replay attacks, you need to create a `nonce` - a value used to associate a client session with an ID token. This value will be preserved and transmitted from the Authentication Request via the ID token. You then match the `nonce` value in the received Token ID with the value of the `nonce` parameter you sent in the Authentication Request.

By using PKCE ([RFC 7636](http://tools.ietf.org/html/rfc7636)), you generate a code called a `code verifier`. Then use it to create a `code challenge` by Base64-URL-encoded the resulting SHA256 hash of the `code verifier`.

The following code demonstrates generating above tokens.
```JS
  // JS

  const { createHash, randomBytes } = require('crypto');
  const base64url = require('./base64url');
  const random = (bytes = 32) => base64url.encode(randomBytes(bytes));
  const state =  random();  const nonce = random();
  const codeVerifier = random();
  const codeChallenge = base64url.encode(createHash('sha256').update(codeVerifier).digest());
  
  // store the state, nonce, code_verifier in your framework's session mechanism,
  // if it is a cookie based solution, it should be httpOnly (not readable by javascript) and encrypted.
```

#### 2. Send an authentication request to **NEMO ID**

The next step is forming an HTTPS `GET` request with the appropriate URI parameters. Note the use of HTTPS rather than HTTP in all the steps of this process; HTTP connections are refused. You should retrieve the base URI from the [Discovery document](#discovery-document), using the `authorization_endpoint` metadata value. The following discussion assumes the base URI is `https://gid.nemoverse.io/auth`.

For a basic request, specify the following parameters:

- `client_id`, which you obtain from successful client registration.

- `response_type`,  which in a basic authorization code flow request should be `code`. (Read more at [`response_type`](#authentication-uri-parameters).)

- `scope`, which in a basic request should be `openid email`. (Đọc thêm tại [`scope`](#scopes-and-claims).)

- `redirect_uri` should be the HTTP endpoint on your server that will receive the response from **NEMO ID**. he value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client,  which you registered. If this value doesn't match an authorized URI, the request will fail with a `redirect_uri_mismatch` error.

- `code_challenge`, is the value generated from `code_verifier`, to satisfy PKCE.

- `code_challenge_method`, in the authorization code flow with PKCE request, the **NEMO ID** must have the value `S256`.

- `state`, should include the value of the anti-forgery unique session token, as well as any other information needed to recover the context when the user returns to your application, e.g., the starting URL. (Read more at `state`.)

- `nonce`  is a random value generated by your app that enables replay protection when present. Giá trị `nonce` sẽ bao gồm trong ID token.

> **Note:** Only the most commonly used parameters are listed above. For a complete list, plus more details about all the parameters, see [Authentication URI parameters](#authentication-uri-parameters).

Here is an example of a complete OpenID Connect authentication URI, with line breaks and spaces for readability::

```
  https://gid.nemoverse.io/auth?
    response_type=code&
    client_id=c72fa486-93f3-4d10-a558-93e878e6e14b.nemoverse&
    scope=openid%20email%20phone_number%20profile&
    redirect_uri=https%3A%2F%2Fwallet.nemoverse.io/callback&
    code_challenge=On553uJ0nsTwUnJix-zDmDjKH73bnzdShkE4vxSojUE&
    code_challenge_method=S256&
    state=csrf%3D38r5719ru3e1%26url%3Dhttps%3A%2F%2Fnemoverse.io%2Fwallet&
    nonce=0394852-3190485-2490358
```

Users are required to give consent if your app requests any new information about them, or if your app requests account access that they have not previously approved.

#### 3. Confirm the anti-forgery state token

The response is sent to the `redirect_uri` that you specified in the [request](#2-send-an-authentication-request-to-nemo-id).  All responses are returned in the query string, as shown below, with line breaks and spaces for readability:

```
  https://wallet.nemoverse.io/callback?
    code=4/P7q7W91a-oMsCeLvIaQm6bTrgtp7&
    state=csrf%3D38r5719ru3e1%26url%3Dhttps%3A%2F%2Fnemoverse.io%2Fwallet&
    iss=https%3A%2F%2Fgid.nemoverse.io
```

On the server, you must confirm that the `state` received from **NEMO ID** matches the session token you created in [Step 1](#1-create-an-anti-forgery-state-token-nonce-code-verifier-and-code-challenge). This round-trip verification helps to ensure that the user, not a malicious script, is making the request.

The following code demonstrates confirming the session tokens that you created in Step 1:

```JS
  // JS

  // Comparing state parameters
  if (req.query.state !== req.cookies['state']) {
    // Throwing unprocessable entity error
    res.status(422).send('Invalid State');
    return;
  }
```

#### 4. Exchange `code` for access token and ID token

The response includes a `code` parameter, a one-time authorization code that your server can exchange for an access token and ID token. Your server makes this exchange by sending an HTTPS `POST` request. The `POST` request is sent to the token endpoint, which you should retrieve from the [Discovery document](#discovery-document) using the `token_endpoint` metadata value.

The following discussion assumes the endpoint is `https://gid.nemoverse.io/token`. The request must include the following parameters in the `POST` body:

<table>
  <tr>
    <th colspan="2">Fields</th>
  </tr>
  <tr>
    <td><code>code</code></td>
    <td>The authorization code that is returned from <a href="#2-send-an-authentication-request-to-nemo-id">the initial request</a>.</td>
  </tr>
  <tr>
    <td><code>client_id</code></td>
    <td>The client ID that you obtain from successful client registration.</td>
  </tr>
  <tr>
    <td><code>redirect_uri</code></td>
    <td>An authorized redirect URI for the given <code>client_id</code> specified, as described in <a href="#setting-up">setting up</a>.</td>
  </tr>
  <tr>
    <td><code>grant_type</code></td>
    <td>This field must contain a value of <code>authorization_code</code>, <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">as defined in the OAuth 2.0 specification</a>.</td>
  </tr>
  <tr>
    <td><code>code_verifier</code></td>
    <td>The value used to create <code>code_challenge</code> in <a href="#2-send-an-authentication-request-to-nemo-id">the initial request</a>.</td>
  </tr>
</table>

> **Note:** If the client is a [Confidential Client](https://www.rfc-editor.org/rfc/rfc6749#section-2.1), the client must send the client_id and client_secret via the HTTP Basic authentication scheme..

The actual request might look like the following example:

```
  POST /token HTTP/1.1
  Host: gid.nemoverse.ioAuthorization: Basic c2lhLWxtczpzaWEtbG1z
  Content-Type: application/x-www-form-urlencoded
  
  code=4/P7q7W91a-oMsCeLvIaQm6bTrgtp7&
  client_id=your-client-id&
  redirect_uri=https%3A%2F%2Fwallet.nemoverse.io/callback&
  grant_type=authorization_code&
  code_verifier=B2D9gzapwlSG4McXvRqw0BiSWYALvASXVzRbHgpz62ZQahVUoOOFmIVEJK70eg3OwQrHDbatMcpUe5Sq2r2nFrKR071URhCtgbHRHxKBa1d5pfp8J9CK6YDCIdl
```

A successful response to this request contains the following fields in a JSON format:

<table>
  <tr>
    <th colspan="2">Fields</th>
  </tr>
  <tr>
    <td><code>access_token</code></td>
    <td>A token that used for accessing the service.</td>
  </tr>
  <tr>
    <td><code>expires_in</code></td>
    <td>The remaining lifetime of the access token in seconds.</td>
  </tr>
  <tr>
    <td><code>id_token</code>page</td>
    <td>A <a href="https://tools.ietf.org/html/rfc7519">JWT</a> that contains identity information about the user that is digitally signed by <strong>NEMO ID</strong></td>
  </tr>
  <tr>
    <td><code>scope</code></td>
    <td>Danh sách phạm vi truy cập được cấp bởi access_token, thể hiện dưới dạng chuỗi phân biệt chữ hoa chữ thường, ngăn cách bằng dấu cách.</td>
  </tr>
  <tr>
    <td><code>token_type</code></td>
    <td>Identifies the type of token returned. At this time, this field always has the value <a href="https://tools.ietf.org/html/rfc6750">Bearer</a>.</td>
  </tr>
  <tr>
    <td><code>refresh_token</code></td>
    <td>(optional) This field is only present if the <code>scope</code> parameter in <a href="#2-send-an-authentication-request-to-nemo-id">authentication request</a> includes <code>offline_access</code>. For details, see <a href="#refresh-token">Refresh token</a>.</td>
  </tr>
</table>

On your server, your should confirm that the `nonce` contained in `id_token` matches the `nonce` parameter you created in [Step 1](#1-create-an-anti-forgery-state-token-nonce-code-verifier-and-code-challenge). The following code demonstrates confirming the session tokens that you created in Step 1:

```JS
  // JS

  const base64url = require('./base64url');
  // Simple decoding example
  const { 0: header, 1: payload, 2: signature, length } = id_token.split('.');
  payload = JSON.parse(base64url.decode(payload));
  // Comparing nonce parameters
  if (payload.nonce !== req.cookies['nonce']) {
    // Throwing unprocessable entity error
    res.status(422).send('Invalid Nonce');
    return;
  }
```

#### 5. Obtain user information from the ID token

An ID Token is a [JWT](https://tools.ietf.org/html/rfc7519) (JSON Web Token), that is, a cryptographically signed Base64-encoded JSON object. Normally, it is critical that you [validate an ID](#validating-an-id-token) token before you use it, but since you are communicating directly with Google over an intermediary-free HTTPS channel and using your client secret to authenticate yourself to **NEMO ID**, you can be confident that the token you receive really comes from **NEMO ID** and is valid. If your server passes the ID token to other components of your app, it is extremely important that the other components [validate the token](#validating-an-id-token) before using it.

Vì hầu hết các thư viện API kết hợp quá trình xác thực với công việc giải mã các giá trị được mã hóa base64url và parse JSON bên trong, nên dù sao đi nữa, bạn có thể sẽ xác thực token khi truy cập các claim trong ID token.

**An ID token's payload**

An ID token is a JSON object containing a set of name/value pairs. Here's an example, formatted for readability:

```JSON
  {
    "sub": "636dbd2bbed6f1c68985abc9",
    "nonce": "0394852-3190485-2490358",
    "at_hash": "cFGywpsU4yKDVbpNrml-yw",
    "aud": "c72fa486-93f3-4d10-a558-93e878e6e14b.nemoverse",
    "exp": 1669605779,
    "iat": 1669602179,
    "iss": "https://gid.nemoverse.io"
  }
```

**NEMO ID**'s ID Tokens may contain the following fields (known as _claims_):

<table>
  <tr>
    <th colspan="1">Claim</th>
    <th colspan="1">Provided</th>
    <th colspan="1">Description</th>
  </tr>
  <tr>
    <td><code>aud</code></td>
    <td>always</td>
    <td>The audience that this ID token is intended for. It must be one of the OAuth 2.0 client IDs of your application.</td>
  </tr>
  <tr>
    <td><code>exp</code></td>
    <td>always</td>
    <td>Expiration time on or after which the ID token must not be accepted. Represented in Unix time (integer seconds).</td>
  </tr>
  <tr>
    <td><code>iat</code></td>
    <td>always</td>
    <td>The time the ID token was issued. Represented in Unix time (integer seconds).</td>
  </tr>
  <tr>
    <td><code>iss</code></td>
    <td>always</td>
    <td>The Issuer Identifier for the Issuer of the response. Always <code>https://gid.nemoverse.io</code> for ID tokens.</td>
  </tr>
  <tr>
    <td><code>sub</code></td>
    <td>always</td>
    <td>An identifier for the user, unique among all <strong>NEMO ID</strong> accounts and never reused. A <strong>NEMO ID</strong> account can have multiple email addresses at different points in time, but the <code>sub</code> value is never changed. Use <code>sub</code> within your application as the unique-identifier key for the user. Maximum length of 255 case-sensitive ASCII characters.</td>
  </tr>
  <tr>
    <td><code>at_hash</code></td>
    <td></td>
    <td>Access token hash. Provides validation that the access token is tied to the identity token. If the ID token is issued with an <code>access_token</code> value in the server flow, this claim is always included</td>
  </tr>
  <tr>
    <td><code>nonce</code></td>
    <td></td>
    <td>The value of the <code>nonce</code> supplied by your app in the authentication request. You should enforce protection against replay attacks by ensuring it is presented only once.</td>
  </tr>
</table>

In addition to the information in the ID token, you can get additional [user profile information](#obtaining-user-profile-information) at our user profile endpoint.

#### 6. Authenticate the user

After obtaining user information from the ID token, you should query your app's user database. If the user already exists in your database, you should start an [application session](#application-session-local-session) for that user if all login requirements are met by the **NEMO ID** response.

If the user does not exist in your user database, you should redirect the user to your new-user sign-up flow. You may be able to auto-register the user based on the information you receive from **NEMO ID**, or at the very least you may be able to pre-populate many of the fields that you require on your registration form.


## Advanced topics

### Access to private resources

The access token you receive back from **NEMO ID** allows you to access private resources, these resource servers will request to the introspection endpoint to [validate the access token](#endpoint-validate-access-token) as shown in the image below.

****![](/public/images/access-private-resource.png)****


### Refresh token

In your request for API access you can request a refresh token to be returned during the [code exchange](#4-exchange-code-for-access-token-and-id-token). A refresh token provides your app continuous access to Google APIs while the user is not present in your application. To request a refresh token, add set the `scope` parameter to `offline_access` in your authentication request.

Considerations:

- Be sure to store the refresh token safely and permanently, because you can only obtain a refresh token the first time that you perform the code exchange flow.

- Refresh tokens can be disabled at any time (due to the user using the single logout function or the user being blocked). In this case, your application needs to clear the user's signed-in status and re-authenticate the user.


### Prompting re-consent

You can prompt the user to re-authorize your app by setting the `prompt` parameter to `consent` in your [authentication request](#2-send-an-authentication-request-to-nemo-id). When `prompt=consent` is included, the consent screen is displayed every time your app requests authorization of scopes of access, even if all scopes were previously granted to your application. For this reason, include `prompt=consent` only when necessary.

For more about the `prompt` parameter, see `prompt` in the [Authentication URI parameters](#authenticating-the-user) table.

### Guest user

To facilitate your app testing experience, **NEMO ID** allows users to log in as guest accounts.\
To use the above feature, your app needs to have the guest account feature enabled. Then, the login interface will look like the image below:

![](/public/images/guest-login.png)

At the same time, your application needs to add the value `guest` to the `scope` parameter (see [Scopes and Claims](#scopes-and-claims)) to be able to identify the currently logged in user is guest account or regular account.

Your app can request to convert a guest account to a regular account at any time by setting the `prompt` parameter to `create` and `login_hint` to the claim `sub` value of the client account's token ID in your [authentication request](#2-send-an-authentication-request-to-nemo-id) and perform the [User authentication](#authenticating-the-user) process again ).

See more in the diagram below:

![](/public/images/upgrade-guest.png)


### Application session (local session)

After the user successfully logs in, the application receives a set of Tokens (ID Token, Access Token, Refresh Token). **The application self-manages the user's login status within the application**. For example, refer to the diagram below:
![](/public/images/application-session.png)


### Logout and single logout

The application performs a user logout from the application (removes the logged in state) and a [revoke refresh token](#endpoint-revoke-token) (in case of use).

**NEMO ID** provides a single logout solution (remove activated token) when users perform certain functions (delete account, change password, change email/phone information, ...). Since active tokens can become invalid, your app needs to check and log out the user in this case. Example flow that checks the token and logs the user out of the application (in case `refresh_token` is used):

![](/public/images/logout.png)


### Authentication URI parameters

The following table gives more complete descriptions of the parameters accepted by **NEMO ID**'s OAuth 2.0 authentication API.

<table>
  <tr>
    <th colspan="1">Parameter</th>
    <th colspan="1">Required</th>
    <th colspan="1">Description</th>
  </tr>
  <tr>
    <td><code>client_id</code></td>
    <td>(Required)</td>
    <td>The client ID string that you obtain from <a href="#setting-up">Setting up</a>.</td>
  </tr>
  <tr>
    <td><code>nonce</code></td>
    <td>(Required)</td>
    <td>A random value generated by your app that enables replay protection.</td>
  </tr>
  <tr>
    <td><code>response_type</code></td>
    <td>(Required)</td>
    <td>The OAuth 2.0 Response Type value determines the authorization flow that will be used, including what parameters are returned from the endpoints used. When using Authorization Code Flow, this value is <code>code</code>.</td>
  </tr>
  <tr>
    <td><code>redirect_uri</code></td>
    <td>(Required)</td>
    <td>Determines where the response is sent. The value of this parameter must exactly match one of the authorized redirect values that you set in the <a href="#setting-up">Setting up</a> step (including the HTTP or HTTPS scheme, case, and trailing '/', if any).</td>
  </tr>
  <tr>
    <td><code>scope</code></td>
    <td>(Required)</td>
    <td>Tham số scope phải bắt đầu bằng giá trị <code>openid</code>, sau đó bao gồm giá trị <code>profile</code>, giá trị <code>email</code> hoặc cả hai.Nếu có giá trị scope <code>profile</code>, thì ID token có thể (nhưng không được bảo đảm) bao gồm các claim <code>profile</code> mặc định của người dùng.Nếu có giá trị scope <code>email</code>, thì ID token sẽ bao gồm các claim <code></code> và <code>email_verified</code>.Ngoài các scope dành riêng cho OpenID này, tham số scope của bạn cũng có thể bao gồm các giá trị scope khác. Tất cả các giá trị scope phải được phân tách bằng khoảng trắng.Để biết thông tin về các scope có sẵn, <a href="#scopes-và-claims">Scopes và Claims</a>.</td>
  </tr>
  <tr>
    <td><code>state</code></td>
    <td>(Optional, but strongly recommended)</td>
    <td>Một chuỗi opaque được round-tripped trong giao thức; nghĩa là, nó được trả về dưới dạng tham số URI trong Basic flow, và trong URI <code>#fragment</code> identifier trong Implicit flow.<code>state</code> có thể hữu ích đối với các request và response tương quan.Vì <code>redirect_uri</code> của bạn có thể đoán được, nên việc sử dụng giá trị <code>state</code> có thể giúp bạn đảm bảo hơn rằng kết nối đến là kết quả của một yêu cầu xác thực do ứng dụng của bạn khởi tạo. Nếu bạn <a href="#1-tạo-anti-forgery-state-token-nonce-code-verifier-và-code-challenge">tạo một chuỗi ngẫu nhiên</a> hoặc mã hóa hàm băm của một số client state (ví dụ: cookie) trong biến <code>state</code> này, thì bạn có thể xác thực response để đảm bảo thêm rằng request và response bắt nguồn từ cùng một trình duyệt. Điều này cung cấp khả năng bảo vệ chống lại các cuộc tấn công như cross-site request forgery (CSRF).</td>
    <td>An opaque string that is round-tripped in the protocol; that is to say, it is returned as a URI parameter in the Basic flow, and in the URI <code>#fragment</code> identifier in the Implicit flow.The <code>state</code> can be useful for correlating requests and responses. Because your <code>redirect_uri</code> can be guessed, using a <code>state</code> value can increase your assurance that an incoming connection is the result of an authentication request initiated by your app. If you <a href="#1-create-an-anti-forgery-state-token-nonce-code-verifier-and-code-challenge">generate a random</a> string or encode the hash of some client state (e.g., a cookie) in this state variable, you can validate the response to additionally ensure that the request and response originated in the same browser. This provides protection against attacks such as cross-site request forgery (CSRF).</td>
  </tr>
  <tr>
    <td><code>code_challenge</code></td>
    <td>(Optional, but strongly recommended)</td>
    <td>Giá trị được tạo ra từ `code_verifier`, để đáp ứng PKCE; xem <a href="#1-tạo-anti-forgery-state-token-nonce-code-verifier-và-code-challenge">Tạo code verifier và code challenge</a>.</td>
  </tr>
  <tr>
    <td><code>code_challenge_method</code></td>
    <td>(Optional, but strongly recommended)</td>
    <td>Trong request của authorization code flow with PKCE của <strong>NEMO ID</strong> phải có giá trị là <code>S256</code></td>
  </tr>
  <tr>
    <td><code>login_hint</code></td>
    <td>(Optional)</td>
    <td>Khi ứng dụng của bạn biết ứng dụng đang cố chứng thực người dùng nào, ứng dụng có thể cung cấp tham số này làm gợi ý cho máy chủ chứng thực. Giá trị có thể là địa chỉ email hoặc chuỗi <code>sub</code>, tương đương với ID của người dùng.</td>
  </tr>
  <tr>
    <td><code>prompt</code></td>
    <td>(Optional)</td>
    <td>Danh sách các giá trị chuỗi được phân tách bằng khoảng trắng chỉ định liệu máy chủ chứng thực có hiển thị cho người dùng chứng thực lại và consent hay không. Các giá trị có thể là:
      <ul>
        <li><code>none</code>: Máy chủ ủy quyền không hiển thị bất kỳ màn hình chứng thực hoặc user consent nào; nó sẽ trả về lỗi nếu người dùng chưa được chứng thực và chưa được cấu hình trước sự đồng ý cho các scope được yêu cầu. Bạn có thể sử dụng <code>none</code> để kiểm tra chứng thực và/hoặc sự đồng ý hiện có.</li>
        <li><code>login</code>: Máy chủ ủy quyền hiển thị cho người dùng chứng thực lại.</li>
        <li><code>consent</code>: Máy chủ ủy quyền hiển thị cho người dùng đồng ý trước khi trả lại thông tin cho client.</li>
        <li><code>select_account</code>: Máy chủ ủy quyền hiển thị cho người dùng chọn tài khoản người dùng. Điều này cho phép người dùng chọn tài khoản có phiên hiện tại hoặc chọn đăng nhập tài khoản khác.</li>
        <li><code>create</code>: Máy chủ ủy quyền hiển thị cho người dùng tạo tài khoản.</li>
        <li><code>guest</code>: Máy chủ cho phép người dùng đăng nhập dưới dạng tài khoản khách</li>
      </ul>
    </td>
  </tr>
</table>

### Validating an ID token

Bạn cần phải xác thực tất cả ID token trên server của mình trừ khi bạn biết rằng chúng đến trực tiếp từ **NEMO ID**. Ví dụ: server của bạn phải xác minh bất kỳ ID token nào mà server nhận được từ các ứng dụng client của bạn là xác thực.

Sau đây là những tình huống phổ biến mà bạn có thể gửi ID token đến server của mình:

- Gửi ID token với các request cần được chứng thực. ID token cho bạn biết người dùng cụ thể tạo request và ID token đó đã được cấp cho client nào.

ID token rất nhạy cảm và có thể bị sử dụng sai nếu bị chặn. Bạn phải đảm bảo rằng các token này được xử lý an toàn bằng cách chỉ truyền chúng qua HTTPS và chỉ qua POST data hoặc trong request headers. Nếu bạn lưu trữ ID token trên máy chủ của mình, bạn cũng phải lưu trữ chúng một cách an toàn.

Một điều làm cho các ID token trở nên hữu ích là bạn có thể chuyển chúng quanh các thành phần khác nhau trong ứng dụng của mình. Các thành phần này có thể sử dụng ID token làm cơ chế chứng thực đơn giản để chứng thực ứng dụng và người dùng. Nhưng trước khi bạn có thể sử dụng thông tin trong ID token hoặc dựa vào thông tin đó để xác nhận rằng người dùng đã được chứng thực, bạn **phải** xác thực thông tin đó.

Việc xác thực ID token yêu cầu một số bước:

1. Xác minh rằng ID token được ký hợp lệ bởi nhà phát hành. Mã thông báo do **NEMO ID** phát hành được ký bằng một trong các chứng chỉ có tại URI được chỉ định trong giá trị metadata `jwks_uri` của [Discovery document](#discovery-document).

2. Xác minh rằng giá trị của claim `iss` trong ID token bằng với `https://gid.nemoverse.io` 

3. Xác minh rằng giá trị của claim `aud` claim trong ID token bằng với client ID của ứng dụng của bạn.

4. Xác minh rằng thời gian hết hạn (claim `exp`) của ID token chưa qua.

Các bước từ 2 đến 4 chỉ liên quan đến so sánh chuỗi và ngày, khá đơn giản nên chúng tôi sẽ không trình bày chi tiết ở đây.

Bước đầu tiên phức tạp hơn và liên quan đến việc kiểm tra chữ ký mật mã. Bạn cần truy xuất keys endpoint [Discovery document](#discovery-document) bằng cách sử dụng giá trị metadata `jwks_uri`, sau đó truy xuất các khóa công khai của **NEMO ID** từ keys endpoint và thực hiện xác thực cục bộ.

Vì **NEMO ID** hiếm khi thay đổi các khóa công khai, nên bạn có thể lưu chúng vào bộ nhớ đệm bằng cách sử dụng chỉ thị bộ đệm của HTTP response. Việc xác thực này yêu cầu truy xuất và parse các chứng chỉ, đồng thời thực hiện các lệnh gọi mã hóa thích hợp để kiểm tra chữ ký. May mắn thay, có sẵn các thư viện được gỡ lỗi tốt bằng nhiều ngôn ngữ khác nhau để thực hiện điều này (xem [jwt.io](https://jwt.io/)).


### Obtaining user profile information

Để có thêm thông tin hồ sơ về người dùng, bạn có thể sử dụng access token (mà ứng dụng của bạn nhận được trong [quy trình xác thực](#chứng-thực-người-dùng)) và chuẩn [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html):

1. Để tuân thủ OpenID, bạn phải bao gồm các giá trị scope `openid profile` trong [yêu cầu chứng thực](#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id).\
   Nếu bạn muốn bao gồm địa chỉ email và số điện thoại của người dùng, bạn có thể chỉ định các giá trị scope bổ sung tương ứng là `email` và `phone_number`. Để chỉ định cả `profile`, `email` và `phone_number`, bạn có thể bao gồm tham số sau trong URI yêu cầu chứng thực:

```
  scope=openid%20profile%20email%20phone_number
```

2. Thêm access token vào authorization header và tạo một HTTPS `GET` request đến userinfo endpoint (mà bạn đã truy xuất từ [Discovery document](#discovery-document) sử dụng giá trị metadata `userinfo_endpoint`). Userinfo response bao gồm thông tin về người dùng, như được mô tả trong [OpenID Connect Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) và giá trị metadata `claims_supported` của Discovery document. Người dùng có thể chọn cung cấp hoặc giữ lại một số trường nhất định, do đó bạn có thể không nhận được thông tin cho mọi trường đối với phạm vi truy cập được phép của mình.


## Phụ lục

### Client metadata

<table>
  <tr>
    <th colspan="1">Field</th>
    <th colspan="1">Required</th>
    <th colspan="1">Description</th>
  </tr>
  <tr>
    <td>Client ID</td>
    <td>(Required)</td>
    <td>ID của client</td>
  </tr>
  <tr>
    <td>Client secret</td>
    <td>(Required, for Confidential Client)</td>
    <td>Chuỗi ký tự dùng cho việc xác thực Client. Cần lưu trữ an toàn và không chia sẻ với bất kỳ ai.</td>
  </tr>
  <tr>
    <td>Redirect URI</td>
    <td>(Required)</td>
    <td>Xác định nơi NEMO ID gửi phản hồi cho yêu cầu chứng thực của bạn.</td>
  </tr>
  <tr>
    <td>App name</td>
    <td>(Required)</td>
    <td>Tên của ứng dụng yêu cầu sự đồng ý của người dùng.</td>
  </tr>
  <tr>
    <td>Logo</td>
    <td>(Required)</td>
    <td>Ảnh hiển thị trên "màn hình đồng ý", sẽ giúp người dùng nhận ra ứng dụng của bạn. Các định dạng hình ảnh được phép là <strong>JPG, PNG</strong>. Logo nên là hình vuông và có kích thước 120px x 120px để có kết quả tốt nhất.</td>
  </tr>
  <tr>
    <td>Application home page</td>
    <td>(Optional)</td>
    <td>Cung cấp cho người dùng một liên kết đến trang chủ của bạn</td>
  </tr>
  <tr>
    <td>Application privacy policy</td>
    <td>(Optional)</td>
    <td>Cung cấp cho người dùng liên kết đến <i>Chính sách bảo mật</i> của bạn</td>
  </tr>
  <tr>
    <td>Application terms of service</td>
    <td>(Optional)</td>
    <td>Cung cấp cho người dùng liên kết đến <i>Điều khoản sử dụng</i> của bạn</td>
  </tr>
</table>

### Scopes và Claims

- Danh sách scope:

<table>
  <tr>
    <th colspan="1">Scope được RP request</th>
    <th colspan="1">Các claim tương ứng OP trả về</th>
  </tr>
  <tr>
    <td>openid (Bắt buộc)</td>
    <td>sub</td>
  </tr>
  <tr>
    <td>email</td>
    <td>email, email_verified</td>
  </tr>
  <tr>
    <td>phone_number</td>
    <td>phone_number, phone_number_verified</td>
  </tr>
  <tr>
    <td>profile</td>
    <td>name, gender, profile_picture</td>
  </tr>
  <tr>
    <td>guest</td>
    <td>is_guest</td>
  </tr>
  <tr>
    <td><i>offline_access</i></td>
    <td><i>Không trả claim.</i> Dùng để yêu cầu refresh token trong quá trình <a href="#4-trao-đổi-code-cho-access-token-và-id-token">trao đổi <code>code</code></a>.</td>
  </tr>
</table>  

- Mô tả các claims:

<table>
  <tr>
    <th colspan="1">Claim</th>
    <th colspan="1">Kiểu dữ liệu</th>
    <th colspan="1">Mô tả</th>
  </tr>
  <tr>
    <td>sub</td>
    <td>string</td>
    <td>ID người dùng.</td>
  </tr>
  <tr>
    <td>name</td>
    <td>string</td>
    <td>Họ tên người dùng</td>
  </tr>
  <tr>
    <td>gender</td>
    <td>string</td>
    <td>ID người dùng.</td>
  </tr>
  <tr>
    <td>profile_picture</td>
    <td>string</td>
    <td>URL ảnh đại diện người dùng.</td>
  </tr>
  <tr>
    <td>email</td>
    <td>string</td>
    <td>ID người dùng.</td>
  </tr>
  <tr>
    <td>email_verified</td>
    <td>boolean</td>
    <td>Email đã xác thực hay chưa.</td>
  </tr>
  <tr>
    <td>phone_number</td>
    <td>string</td>
    <td>SĐT người dùng.</td>
  </tr>
  <tr>
    <td>phone_number_verified</td>
    <td>boolean</td>
    <td>SĐT đã xác thực hay chưa.</td>
  </tr>
  <tr>
    <td>is_guest</td>
    <td>boolean</td>
    <td>Tài khoản có phải tài khoản khách không.</td>
  </tr>
</table>

### Discovery document

Giao thức OpenID Connect yêu cầu sử dụng nhiều endpoint để chứng thực người dùng, và để yêu cầu các tài nguyên bao gồm các token và thông tin người dùng.

Để đơn giản hóa việc triển khai và tăng tính linh hoạt, OpenID Connect cho phép sử dụng "Tài liệu khám phá" (Discovery document), tài liệu JSON được tìm thấy tại một vị trí phổ biến, chứa các cặp key-value cung cấp chi tiết về cấu hình của nhà cung cấp OpenID Connect, bao gồm URI endpoint của authorization, token, revocation và userinfo. Discovery document cho dịch vụ OpenID Connect của **NEMO ID** có thể được lấy từ:

```
  https://gid.nemoverse.io/.well-known/openid-configuration
```

Để sử dụng các dịch vụ OpenID Connect của **NEMO ID**, bạn nên hard-code Discovery document URI trên vào ứng dụng của bạn. Ứng dụng của bạn fetch document, áp dụng các quy tắc bộ nhớ đệm (caching rule) trong response, sau đó truy xuất các endpoint URI từ đó nếu cần. Ví dụ: để chứng thực người dùng, code của bạn sẽ truy xuất giá trị metadata `authorization_endpoint` (`https://gid.nemoverse.io/auth` trong ví dụ bên dưới) làm base URI cho các yêu cầu chứng thực được gửi tới **NEMO ID**.

Đây là một ví dụ về một tài liệu như vậy; tên trường là những tên được chỉ định trong [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) (tham khảo tài liệu đó để biết ý nghĩa của chúng). Các giá trị hoàn toàn mang tính minh họa và có thể thay đổi, mặc dù chúng được sao chép từ phiên bản gần đây của **NEMO ID** Discovery document thực tế:

```JSON
  {
    "authorization_endpoint": "https://gid.nemoverse.io/auth",
    "claims_parameter_supported": false,
    "claims_supported": [
      "sub",
      "email",
      "email_verified",
      "name",
      "gender",
      "profile_picture",
      "phone_number",
      "phone_number_verified",
      "sid",
      "auth_time",
      "iss"
    ],
    "code_challenge_methods_supported": [
      "S256"
    ],
    "end_session_endpoint": "https://gid.nemoverse.io/session/end",
    "grant_types_supported": [
      "implicit",
      "authorization_code",
      "refresh_token"
    ],
    "id_token_signing_alg_values_supported": [
      "ES256",
      "EdDSA",
      "PS256",
      "RS256"
    ],
    "issuer": "https://gid.nemoverse.io",
    "jwks_uri": "https://gid.nemoverse.io/jwks",
    "registration_endpoint": "https://gid.nemoverse.io/reg",
    "authorization_response_iss_parameter_supported": true,
    "response_modes_supported": [
      "form_post",
      "fragment",
      "query"
    ],
    "response_types_supported": [
      "code id_token",
      "code",
      "id_token",
      "none"
    ],
    "scopes_supported": [
      "openid",
      "offline_access",
      "email",
      "profile"
    ],
    "subject_types_supported": [
      "public"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_jwt",
      "client_secret_post",
      "private_key_jwt",
      "none"
    ],
    "token_endpoint_auth_signing_alg_values_supported": [
      "HS256",
      "RS256",
      "PS256",
      "ES256",
      "EdDSA"
    ],
    "token_endpoint": "https://gid.nemoverse.io/token",
    "request_object_signing_alg_values_supported": [
      "HS256",
      "RS256",
      "PS256",
      "ES256",
      "EdDSA"
    ],
    "request_parameter_supported": false,
    "request_uri_parameter_supported": true,
    "require_request_uri_registration": true,
    "userinfo_endpoint": "https://gid.nemoverse.io/me",
    "introspection_endpoint": "https://gid.nemoverse.io/token/introspection",
    "introspection_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_jwt",
      "client_secret_post",
      "private_key_jwt",
      "none"
    ],
    "introspection_endpoint_auth_signing_alg_values_supported": [
      "HS256",
      "RS256",
      "PS256",
      "ES256",
      "EdDSA"
    ],
    "revocation_endpoint": "https://gid.nemoverse.io/token/revocation",
    "revocation_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_jwt",
      "client_secret_post",
      "private_key_jwt",
      "none"
    ],
    "revocation_endpoint_auth_signing_alg_values_supported": [
      "HS256",
      "RS256",
      "PS256",
      "ES256",
      "EdDSA"
    ],
    "claim_types_supported": [
      "normal"
    ]
  }
```

Bạn có thể tránh HTTP round-trip bằng cách caching các giá trị từ Discovery document. Các Standard HTTP caching header được sử dụng và phải được tuân thủ.


## Các endpoint thường sử dụng:

<table>
  <tr>
    <th colspan="1">Endpoint</th>
    <th colspan="1">URL</th>
  </tr>
  <tr>
    <td>Server discovery (wellKnown)</td>
    <td>/.well-known/openid-configuration</td>
  </tr>
  <tr>
    <td>Authorization</td>
    <td>/auth</td>
  </tr>
  <tr>
    <td>Token</td>
    <td>/.well-known/openid-configuration</td>
  </tr>
  <tr>
    <td>User Info</td>
    <td>/me</td>
  </tr>
  <tr>
    <td>End Session</td>
    <td>/session/end</td>
  </tr>
  <tr>
    <td>Introspection</td>
    <td>/token/introspection</td>
  </tr>
</table>

Tải Postman collection của **NEMO ID** [tại đây](https://drive.google.com/file/d/1G7l8Oz8i9YgmWOhslU57OlVytKM7LkDh/view?usp=sharing) (Cần request để truy cập).


### Endpoint authorization

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">Endpoint dùng để request đăng nhập user phía NEMO ID.</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/auth</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>GET</td>
  </tr>
  <tr>
    <td>Params</td>
    <td>
      <ul>
        <li><i>client_id</i> (Required): Client ID.</li>
        <li><i>response_type</i> (Required): Kiểu flow đăng nhập.</li>
        <li><i>redirect_uri</i> (Required): URI mà sau khi đăng nhập được redirect về.</li>
        <li><i>scope</i> (Required): Scope mà Client muốn OP trả về.</li>
        <li><i>code_challenge</i> (Required): Mã hash trong PKCE flow.</li>
        <li><i>state</i> (Optional): Một random string để đảm bảo state trước lúc đăng nhập và sau khi redirect về client.</li>
        <li><i>prompt</i> (Optional): Truyền thêm prompt=create để redirect trực tiếp đến trang signup. Nếu không, redirect đến trang signin.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Ví dụ</td>
    <td>https://gid.nemoverse.io/auth?client_id=nemo&response_type=code&redirect_uri=http://localhost:3000&scope=openid%20profile%20offline_access&code_challenge=On553uJ0nsTwUnJix-zDmDjKH73bnzdShkE4vxSojUE&code_challenge_method=S256</td>
  </tr>
  <tr>
    <td>Response</td>
    <td>Page đăng nhập/ đăng ký</td>
  </tr>
</table>


### Endpoint get token

**(Nếu Client là native thì bỏ qua header Authorization)**

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">Endpoint dùng để get bộ token (IT, AT, RT).</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/token</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>POST</td>
  </tr>
  <tr>
    <td>Body</td>
    <td>
      <ul>
        <li>code<i>: Authorization Code.</i></li>
        <li>client_id<i>: Client ID.</i></li>
        <li>grant_type<i>: "authorization_code".</i></li>
        <li>redirect_uri<i>: URI sau khi đăng nhập được redirect về.</i></li>
        <li><i>code_verifier</i>: Đoạn code được decode từ <i>code_challenge</i> thông qua giải thuật <i>code_challenge_method</i>.</li>
      </ul>
      <p>Ví dụ:</p>
      <code>{ "code": "o0YGAoiEi3ouJDCbPF0b5VdgOwMELe6QVLXiqaC19XJ", "client_id": "nemo", "grant_type": "authorization_code", "redirect_uri": "http://localhost:3000", "code_verifier": "B2D9gzapwlSG4McXvRqw0BiSWYALvASXVzRbHgpz62ZQahVUoOOFmIVEJK70eg3OwQrHDbatMcpUe5Sq2r2nFrKR071URhCtgbHRHxKBa1d5pfp8J9CK6YDCIdl" }</code>
    </td>
  </tr>
  <tr>
    <td>Headers</td>
    <td>
      <code>{  "Content-Type": "application/x-www-form-urlencoded",  "Authorization": "Basic " + Base64("[client_id]:[client_secret]")}</code>
      <p>Trong đó:</p>
      <ul>
        <li><i>client_id</i>: Client ID.</li>
        <li><i>client_secret</i>: Client Secret.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Response khi code hợp lệ (200)</td>
    <td><code>{ "access_token": "H_Mf22Cj0FnYIw3KY65BYJOBsUjCufmqAafJLWtvium",   "expires_in": 3600,   "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkNUdPY293M2lQa1R6SndBZG5kYlFRR2dHNTRucy1JQ1JlaXRYcGFPSDQifQ.eyJzdWIiOiI2MmNiY2Q2OGMwMGJjODJkMzhmNmZhMTMiLCJhdF9oYXNoIjoiRmxJY0NtaW90ZW43LXZhZWY1U2NGUSIsImF1ZCI6Im5lbW8iLCJleHAiOjE2NjUzNzMyOTMsImlhdCI6MTY2NTM2OTY5MywiaXNzIjoiaHR0cHM6Ly9kZXYxLmhlcmFwby52biJ9.WXqw9RqoF9wdbGHBah8BP386HMN-j250qsmDsM2k0pJa_6y2VFseTB_McsJoVD0mPa_iTvyKX0vUz25A4lJfUM8z4pBmGu3FJpS4Vodn2dlvOHn5HcJUvU2jZYyhgXAo8fj0O3hSUmxoGlzkLiv3F6Ui0sGrPV6eM_7FXTUHUkLxOSFHZIcj6zcp5COclcU-buQJSZUThBpaRtt_R6719Oi3pkoYm3whQZzc8sL6ISGBHG1y-abjLPXQnQilnxh42K9miWXG_rtRxUJGPjdHrVR41k4gl-f-s5PbzfXvpKROfE65DhcyzO-o6Nlw_AHPuADnI_dY5k5p2Y_Mig1fUw",   "refresh_token": "R3zdIkbIyNnRn5AHvtz1OE3vb_tbEJ5xtywpVzoxru-",   "scope": "openid profile",   "token_type": "Bearer" }</code></td>
  </tr>
  <tr>
    <td>Response khi code không hợp lệ (400)</td>
    <td><code>{ "error": "invalid_grant",   "error_description": "grant request is invalid" }</code></td>
  </tr>
</table>

### Endpoint validate Access Token:

**(Nếu Client là native thì bỏ qua header Authorization và thêm field client_id trong body)**

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">API validate Access Token</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/token/introspection</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>POST</td>
  </tr>
  <tr>
    <td>Body</td>
    <td>
      <ul>
        <li><i>token</i>: Access Token.</li>
        <li><i>client_id</i>: Client ID.</li>
      </ul>
      <p>Ví dụ:</p>
      <code>{  token: "hldVr1QRjTF65eKoEoxQI5YLot12NyrUnVlkAZV4W_j"  client_id: "nemo"}</code>
    </td>
  </tr>
  <tr>
    <td>Headers</td>
    <td>
      <code>{  "Content-Type": "application/x-www-form-urlencoded",  "Authorization": "Basic " + Base64("[client_id]:[client_secret]")}</code>
      <p>Trong đó:</p>
      <ul>
        <li><i>client_id</i>: Client ID.</li>
        <li><i>client_secret</i>: Client Secret.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Response khi code hợp lệ (200)</td>
    <td><code>{ "active": true,   "sub": "62cbcd68c00bc82d38f6fa13",   "client_id": "sia-lms",   "exp": 1667212097,   "iat": 1667208497,   "iss": "https://gid.nemoverse.io",   "scope": "openid profile",   "token_type": "Bearer" }</code></td>
  </tr>
  <tr>
    <td>Response khi code không hợp lệ (401)</td>
    <td><code>{ "active": false }</code></td>
  </tr>
</table>

### Endpoint get thông tin người dùng:

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">Endpoint get thông tin người dùng.</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/me</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>GET</td>
  </tr>
  <tr>
    <td>Body</td>
    <td>
      <ul>
        <li><i>token</i>: Access Token.</li>
        <li><i>client_id</i>: Client ID.</li>
      </ul>
      <p>Ví dụ:</p>
      <code>{ token: "hldVr1QRjTF65eKoEoxQI5YLot12NyrUnVlkAZV4W_j"  client_id: "nemo" }</code>
    </td>
  </tr>
  <tr>
    <td>Headers</td>
    <td><code>{ "Authorization": "Bearer [access_token]" }</code></td>
  </tr>
  <tr>
    <td>Response khi code hợp lệ (200)</td>
    <td><code>{ "sub": "62cbcd68c00bc82d38f6fa13",   "name": "tiến huỳnh ",   "gender": "male", "profile_picture": "https://gid.nemoverse.io/public/upload/10-14-Night-f9f9.jpg",   "email": "tien.huynh@gosu.vn",   "email_verified": true,   "phone_number": "",   "phone_number_verified": false }</code></td>
  </tr>
  <tr>
    <td>Response khi code không hợp lệ (401)</td>
    <td><code>{ "error": "invalid_token",   "error_description": "invalid token provided" }</code></td>
  </tr>
</table>

### Endpoint refresh token

**(Nếu Client là native thì bỏ qua header Authorization)**

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">Endpoint refresh ID Token và Access Token mới.</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/token</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>POST</td>
  </tr>
  <tr>
    <td>Body</td>
    <td>
      <ul>
        <li><i>grant_type</i>: "refresh_token".</li>
        <li><i>client_id</i>: Client ID.</li>
        <li><i>refresh_token</i>: Refresh Token.</li>
      </ul>
    <p>Ví dụ:</p>
    <code>{ "client_id": "nemo",  grant_type: "refresh_token",  refresh_token: "2yJrqnbZFFkMV2Dw8662wzjNkIYAi3cA36dzX3Clonz" }</code>
  </tr>
  <tr>
    <td>Headers</td>
    <td>
      <code>{  "Content-Type": "application/x-www-form-urlencoded",  "Authorization": "Basic " + Base64("[client_id]:[client_secret]")}</code>
      <p>Trong đó:</p>
      <ul>
        <li><i>client_id</i>: Client ID.</li>
        <li><i>client_secret</i>: Client Secret.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Response khi code hợp lệ (200)</td>
    <td><code>{ "access_token": "fSoRXvSOGq1rJKpuonBWlL_R7SR4_96OBvOL2uRt9pF",   "expires_in": 3600,   "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkNUdPY293M2lQa1R6SndBZG5kYlFRR2dHNTRucy1JQ1JlaXRYcGFPSDQifQ.eyJzdWIiOiI2MzVjZmU3OTBiY2FkYTA4NTk5OWI0MzQiLCJhdF9oYXNoIjoiTklUZldnX2xJVXU4WjRsMVBQaVNsQSIsImF1ZCI6InNpYS1sbXMiLCJleHAiOjE2NjcyMTk1MDYsImlhdCI6MTY2NzIxNTkwNiwiaXNzIjoiaHR0cHM6Ly9naWQtdWF0Lm5lbW92ZXJzZS5pbyJ9.ki6W_OUnfGYiTPe-0b7Id8C7aWVqTBmnV5V4WJ_9Lh9ayJj9-0mNjHqV3Im1EY21ywPYVQgX4EOiGsThOT18Hn8RAzitN7YMxzLtdck48MhLT92l8VLe4RFGUpUf-eRBbnPJSf7Udb9jJEW9Q_q10zlr8DGmeSEPdsbChw76XF3QTj2d5VXebSGc-_CprF3V1nb4_tT326fFiFB1nNJIbIx1rs4NMKP-VUSx8Z0I50sQ-yREeaopmAqe94fAzB-MZi5EDoK9lG5H01bJsUY5ERI-HhAMbGKGdyVYdEl56W-utdgMqIBJuyGeHy6zXOqKzcKi5QdKea5n6a9K9PQ43w",   "refresh_token": "2yJrqnbZFFkMV2Dw8662wzjNkIYAi3cA36dzX3Clonz",   "scope": "openid profile",   "token_type": "Bearer" }</code></td>
  </tr>
  <tr>
    <td>Response khi code không hợp lệ (400)</td>
    <td><code>{ "error": "invalid_grant",   "error_description": "grant request is invalid" }</code></td>
  </tr>
</table>

### Endpoint revoke token

**(Nếu Client là native thì bỏ qua header Authorization và thêm field client_id trong body).**

<table>
  <tr>
    <th colspan="1">Mô tả</th>
    <th colspan="1">API revoke refresh token hoặc access token.</th>
  </tr>
  <tr>
    <td>URL</td>
    <td>https://gid.nemoverse.io/token/revocation</td>
  </tr>
  <tr>
    <td>Method</td>
    <td>POST</td>
  </tr>
  <tr>
    <td>Body</td>
    <td>
      <ul>
        <li><i>token</i>: Refresh Token.</li>
        <li><i>token_type_hint</i>: "refresh_token".</li>
        <li><i>client_id</i>: Client ID.</li>
      </ul>
    <p>Ví dụ:</p>
    <code>{  token: "2yJrqnbZFFkMV2Dw8662wzjNkIYAi3cA36dzX3Clonz", token_type_hint: "refresh_token", client_id: "nemo" }</code>
  </tr>
  <tr>
    <td>Headers</td>
    <td>
      <code>{  "Content-Type": "application/x-www-form-urlencoded",  "Authorization": "Basic " + Base64("[client_id]:[client_secret]")}</code>
      <p>Trong đó:</p>
      <ul>
        <li><i>client_id</i>: Client ID.</li>
        <li><i>client_secret</i>: Client Secret.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Response khi code hợp lệ (200)</td>
    <td>(Không data).</td>
  </tr>
</table>

## Client libraries

- [Android SDK](https://github.com/gosusdk/android-nemosdk_iap_demo)

- [iOS SDK](https://github.com/gosusdk/ios-nemosdk_iap_demo)


## Tuân thủ OpenID Connect

Hệ thống xác thực OAuth 2.0 của **NEMO ID** hỗ trợ các [tính năng bắt buộc](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI) của đặc tả [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
