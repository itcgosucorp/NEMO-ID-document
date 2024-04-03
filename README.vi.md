# Tài liệu NEMO ID

Tài liệu này mô tả việc triển khai OAuth 2.0 của **NEMO ID** để chứng thực, tuân theo đặc điểm kỹ thuật của [OpenID Connect](https://openid.net/connect/).

[Identity, Authentication + OAuth = OpenID Connect](http://www.youtube.com/watch?feature=player_embedded&v=Kb56GzQ2pSk)

Đọc nội dung này bằng các ngôn ngữ khác: [English](README.md), [Tiếng Việt](README.vi.md)


## Thiết lập

Trước khi ứng dụng của bạn có thể sử dụng hệ thống chứng thực OAuth 2.0 của **NEMO ID** để đăng nhập người dùng, bạn phải đăng ký ứng dụng với admin để lấy OAuth 2.0 credentials, đặt redirect URI và (tùy chọn) tùy chỉnh thông tin thương hiệu mà người dùng của bạn nhìn thấy trên màn hình đăng nhập (login), màn hình đồng ý (consent) của người dùng.

![](/public/images/login-consent.png)

**_Ví dụ các thiết lập:_**

_\* Chữ in nghiêng có giá trị thay đổi tùy theo ứng dụng đăng ký_

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
    <td><i>(Gửi file ảnh cho admin)</i></td>
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
    <th colspan="2">Credential (Admin trả về sau khi đăng ký client thành công)</th>
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


## Truy cập dịch vụ

**NEMO ID** cung cấp các thư viện mà bạn có thể sử dụng để xử lý nhiều chi tiết triển khai chứng thực người dùng.

> **Lưu ý:** Với ý nghĩa bảo mật của việc triển khai chính xác, chúng tôi đặc biệt khuyến khích bạn tận dụng thư viện hoặc dịch vụ được viết sẵn. Việc chứng thực người dùng đúng cách là rất quan trọng đối với sự an toàn và bảo mật của họ và của bạn, đồng thời sử dụng mã được gỡ lỗi tốt do người khác viết thường là cách tốt nhất. Để biết thêm thông tin, hãy xem [Client libraries](#client-libraries).

Nếu bạn **chọn không sử dụng thư viện**, hãy làm theo hướng dẫn trong phần còn lại của tài liệu này, phần này mô tả các luồng HTTP request bên dưới các thư viện có sẵn.


## Chứng thực người dùng

Chứng thực người dùng liên quan đến việc lấy ID token và xác thực nó. [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) là một tính năng tiêu chuẩn hóa của [OpenID Connect](https://openid.net/connect/) được thiết kế để sử dụng trong việc chia sẻ xác nhận danh tính trên Internet.

Các phương pháp được sử dụng phổ biến nhất để chứng thực người dùng và lấy ID token được gọi là "Authorization code" flow và "Implicit" flow.

- **Authorization code flow** -- flow được sử dụng phổ biến nhất, dành cho các web app truyền thống cũng như native / mobile app.\
  Bắt đầu với việc chuyển hướng trình duyệt đến / từ OP để người dùng chứng thực và consent, sau đó gửi một back-channel request để truy xuất ID token.\
  Luồng này cung cấp bảo mật tối ưu, vì các token không được tiết lộ cho trình duyệt và client cũng có thể được chứng thực.

- **Implicit flow** -- dành cho các app dựa trên trình duyệt (JavaScript) mà không có backend.\
  ID token được nhận trực tiếp với response chuyển hướng từ OP. Không yêu cầu back-channel request.

Tài liệu này mô tả cách thực hiện "Authorization code" flow (with PKCE) để chứng thực người dùng. "Implicit" flow phức tạp hơn đáng kể do rủi ro bảo mật trong việc xử lý và sử dụng mã thông báo ở client side (front-end).


### Authorization code flow With Proof Key of Code Exchange (PKCE)

PKCE ([RFC 7636](http://tools.ietf.org/html/rfc7636)) là một phần mở rộng của Authorization Code flow để ngăn chặn các tấn công CSRF và authorization code injection. **NEMO ID** sử dụng Authorization Code flow với PKCE nhằm mục đích an toàn và bảo mật.

![](/public//images//auth-code-pkce-flow.png)

_Flow hoạt động của Authorization Code flow with PKCE_

Đảm bảo rằng bạn đã [thiết lập ứng dụng](#thiết-lập) của mình để cho phép ứng dụng sử dụng các giao thức này và chứng thực người dùng của bạn. Khi người dùng đăng nhập bằng **NEMO ID**, bạn cần phải:

1. [Tạo anti-forgery state token, nonce, code verifier và code challenge](#1-tạo-anti-forgery-state-token-nonce-code-verifier-và-code-challenge)

2. [Gửi yêu cầu chứng thực tới **NEMO ID**](#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id)

3. [Xác nhận anti-forgery state token](#3-xác-nhận-anti-forgery-state-token)

4. [Trao đổi `code` lấy access token và ID token](#4-trao-đổi-code-cho-access-token-và-id-token)

5. [Lấy thông tin người dùng](#5-lấy-thông-tin-người-dùng)

6. [Chứng thực người dùng](#6-chứng-thực-người-dùng)

#### 1. Tạo anti-forgery state token, nonce, code verifier và code challenge

Bạn phải bảo vệ sự an toàn cho người dùng bằng cách ngăn chặn các cuộc tấn công giả mạo yêu cầu (request forgery). Bước đầu tiên là tạo một session token duy nhất giữ trạng thái (state) giữa ứng dụng và client của người dùng. Sau đó bạn so khớp session token duy nhất này với authentication response trả về bởi **NEMO ID** để xác minh rằng người dùng đang thực hiện yêu cầu chứ không phải một "kẻ tấn công". Các token này thường được gọi là cross-site request forgery (CSRF) token.

Để giảm thiểu các replay attack, bạn cần tạo `nonce` - một giá trị dùng để liên kết một phiên của client với một ID token. Giá trị này sẽ được giữ nguyên và truyền từ Authentication Request qua ID token. Sau đó bạn so khớp giá trị `nonce` trong ID Token khi nhận được với giá trị bạn tham số `nonce` bạn đã gửi trong Authentication Request.

Với việc sử dụng PKCE ([RFC 7636](http://tools.ietf.org/html/rfc7636)), bạn tạo ra một mã gọi là `code verifier`. Sau đó, sử dụng nó để tạo `code challenge` bằng cách thực hiện Base64-URL-encoded chuỗi kết quả hash SHA256 của `code verifier`.

Đoạn code sau minh họa việc tạo các mã trên.
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

#### 2. Gửi yêu cầu chứng thực tới NEMO ID

Bước tiếp theo là hình thành một yêu cầu HTTPS `GET` với các tham số URI thích hợp. Lưu ý việc sử dụng HTTPS thay vì HTTP trong tất cả các bước của quy trình này; Kết nối HTTP sẽ bị từ chối. Bạn nên truy xuất base URI từ [Discovery document](#discovery-document), sử dụng giá trị của `authorization_endpoint` metadata. Phần bên dưới giả định base URI là `https://gid.nemoverse.io/auth`.

Đối với yêu cầu cơ bản, hãy chỉ định các tham số sau:

- `client_id`, mà bạn có được khi đăng ký ứng dụng.

- `response_type`, trong request của authorization code flow cơ bản là `code`. (Đọc thêm tại [`response_type`](#authentication-uri-parameters).)

- `scope`, trong yêu cầu cơ bản là `openid email`. (Đọc thêm tại [`scope`](#scopes-và-claims).)

- `redirect_uri` phải là HTTP endpoint trên server của bạn mà sẽ nhận response từ **NEMO ID**. Giá trị phải khớp chính xác với một trong các redirect URIs cho OAuth 2.0 client, mà bạn đã đăng ký. Nếu giá trị này không khớp với một URI đã xác thực, yêu cầu sẽ thất bại với lỗi `redirect_uri_mismatch`.

- `code_challenge`, là giá trị được tạo ra từ `code_verifier`, để đáp ứng PKCE.

- `code_challenge_method`, trong request của authorization code flow with PKCE của **NEMO ID** phải có giá trị là `S256`.

- `state` phải bao gồm giá trị của anti-forgery unique session token, cũng như bất kỳ thông tin nào khác cần thiết để khôi phục ngữ cảnh (context) khi người dùng quay lại ứng dụng của bạn, ví dụ: starting URL. (Đọc thêm tại `state`.)

- `nonce` là một giá trị ngẫu nhiên do ứng dụng của bạn tạo ra để bảo vệ tấn công replay. Giá trị `nonce` sẽ bao gồm trong ID token.

> **Lưu ý:** Chỉ những tham số được sử dụng phổ biến nhất được liệt kê ở trên. Để biết danh sách đầy đủ, cùng với các chi tiết khác về tất cả các tham số, hãy xem [Authentication URI parameters](#authentication-uri-parameters).

Dưới đây là một ví dụ về OpenID Connect authentication URI hoàn chỉnh, với các ngắt dòng và khoảng trắng để dễ đọc:

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

Người dùng bắt buộc phải đồng ý (consent) nếu ứng dụng của bạn yêu cầu bất kỳ thông tin mới nào về họ hoặc nếu ứng dụng của bạn yêu cầu quyền truy cập vào tài khoản mà họ chưa phê duyệt trước đó.

#### 3. Xác nhận anti-forgery state token

Response được gửi đến `redirect_uri` mà bạn đã chỉ định trong [request](#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id). Tất cả các response được trả về trong query string, như dưới đây, với các ngắt dòng và khoảng trắng để dễ đọc:

```
  https://wallet.nemoverse.io/callback?
    code=4/P7q7W91a-oMsCeLvIaQm6bTrgtp7&
    state=csrf%3D38r5719ru3e1%26url%3Dhttps%3A%2F%2Fnemoverse.io%2Fwallet&
    iss=https%3A%2F%2Fgid.nemoverse.io
```

Trên server, bạn phải xác nhận rằng `state` nhận được từ **NEMO ID** khớp với session token mà bạn đã tạo ở [Bước 1](#1-tạo-anti-forgery-state-token-nonce-code-verifier-và-code-challenge). Quá trình xác minh hai chiều này giúp đảm bảo rằng người dùng, chứ không phải mã độc, đang thực hiện request.

Đoạn mã sau minh họa việc xác nhận session token mà bạn đã tạo ở Bước 1:

```JS
  // JS

  // Comparing state parameters
  if (req.query.state !== req.cookies['state']) {
    // Throwing unprocessable entity error
    res.status(422).send('Invalid State');
    return;
  }
```

#### 4. Trao đổi `code` cho access token và ID token

Response bao gồm một parameter `code`, là một mã chứng thực sử dụng một lần mà server của bạn có thể dùng để trao đổi lấy access token và ID token. Server của bạn thực hiện trao đổi này bằng cách gửi một HTTPS `POST` request. `POST` request được gửi đến token endpoint, mà bạn có thể truy xuất từ [Discovery document](#discovery-document) qua giá trị của metadata `token_endpoint`.

Phần bên dưới giả định endpoint này là `https://gid.nemoverse.io/token`. Request phải bao gồm các tham số sau trong `POST` body:

<table>
  <tr>
    <th colspan="2">Fields</th>
  </tr>
  <tr>
    <td><code>code</code></td>
    <td>Authorization code được trả về từ <a href="#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id">request ban đầu</a>.</td>
  </tr>
  <tr>
    <td><code>client_id</code></td>
    <td>Client ID mà bạn có được khi đăng ký ứng dụng.</td>
  </tr>
  <tr>
    <td><code>redirect_uri</code></td>
    <td>Redirect URI đã được xác thực cho <code>client_id</code> chỉ định, như mô tả tại phần <a href="#thiết-lập">Thiết lập</a>.</td>
  </tr>
  <tr>
    <td><code>grant_type</code></td>
    <td> Trường này phải chứa giá trị là <code>authorization_code</code>, như đã <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">được xác định trong đặc tả OAuth 2.0</a>).</td>
  </tr>
  <tr>
    <td><code>code_verifier</code></td>
    <td>Giá trị đã dùng để tạo <code>code_challenge</code> trong <a href="#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id">request ban đầu</a>.</td>
  </tr>
</table>

> **Lưu ý:** Nếu client là một [Confidential Client](https://www.rfc-editor.org/rfc/rfc6749#section-2.1), client phải gửi client_id và client_secret qua HTTP Basic authentication scheme.

Request thực tế có thể giống như ví dụ sau:

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

Một response thành công cho request này chứa các field sau dưới dạng JSON:

<table>
  <tr>
    <th colspan="2">Fields</th>
  </tr>
  <tr>
    <td><code>access_token</code></td>
    <td>Token dùng để truy cập dịch vụ.</td>
  </tr>
  <tr>
    <td><code>expires_in</code></td>
    <td>Thời gian tồn tại còn lại của access token tính bằng giây.</td>
  </tr>
  <tr>
    <td><code>id_token</code>page</td>
    <td>Một <a href="https://tools.ietf.org/html/rfc7519">JWT</a> chứa thông tin định danh về user được ký bởi <strong>NEMO ID</strong></td>
  </tr>
  <tr>
    <td><code>scope</code></td>
    <td>Danh sách phạm vi truy cập được cấp bởi access_token, thể hiện dưới dạng chuỗi phân biệt chữ hoa chữ thường, ngăn cách bằng dấu cách.</td>
  </tr>
  <tr>
    <td><code>token_type</code></td>
    <td>Xác định loại token được trả lại. Tại thời điểm này, trường này luôn có giá trị <a href="https://tools.ietf.org/html/rfc6750">Bearer</a>.</td>
  </tr>
  <tr>
    <td><code>refresh_token</code></td>
    <td>(optional) Trường này chỉ xuất hiện nếu tham số <code>scope</code> trong <a href="#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id">yêu cầu chứng thực</a> có chứa giá trị <code>offline_access</code>. Để biết chi tiết, hãy xem <a href="#refresh-token">Refresh token</a>.</td>
  </tr>
</table>

Trên server, bạn phải xác nhận rằng `nonce` chứa trong `id_token` khớp với tham số `nonce` mà bạn đã tạo ở [Bước 1](#1-tạo-anti-forgery-state-token-nonce-code-verifier-và-code-challenge). Đoạn mã sau minh họa việc xác nhận `nonce` mà bạn đã tạo ở Bước 1:

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

#### 5. Lấy thông tin người dùng

ID Token là một [JWT](https://tools.ietf.org/html/rfc7519) (JSON Web Token), nghĩa là một đối tượng Base64-encoded JSON đã được ký bằng mật mã. Thông thường, điều quan trọng là bạn phải [xác thực ID token](#xác-thực-id-token) trước khi bạn sử dụng nó. Tuy nhiên, trường hợp bạn đang giao tiếp trực tiếp với **NEMO ID** qua kênh HTTPS mà không có trung gian và sử dụng client secret để chứng thực ứng dụng với **NEMO ID** nên bạn có thể yên tâm rằng token bạn nhận thực sự đến từ **NEMO ID** và hợp lệ. Nếu server của bạn chuyển ID token cho các thành phần khác trong ứng dụng, điều cực kỳ quan trọng là các thành phần khác phải [xác thực token](#xác-thực-id-token) trước khi sử dụng.

Vì hầu hết các thư viện API kết hợp quá trình xác thực với công việc giải mã các giá trị được mã hóa base64url và parse JSON bên trong, nên dù sao đi nữa, bạn có thể sẽ xác thực token khi truy cập các claim trong ID token.

**ID token payload**

ID token là một JSON object gồm một bộ các cặp name/value. Đây là một ví dụ, được định dạng để dễ đọc:

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

**NEMO ID**'s ID Tokens có thể chứa các trường sau (được gọi là _claim_):

<table>
  <tr>
    <th colspan="1">Claim</th>
    <th colspan="1">Provided</th>
    <th colspan="1">Description</th>
  </tr>
  <tr>
    <td><code>aud</code></td>
    <td>always</td>
    <td>Đối tượng mà ID token này dành cho. Nó phải là một trong các client ID của ứng dụng của bạn.</td>
  </tr>
  <tr>
    <td><code>exp</code></td>
    <td>always</td>
    <td>Thời gian hết hạn vào hoặc sau thời điểm đó ID token không được chấp nhận. Được biểu thị bằng thời gian Unix (số nguyên giây)</td>
  </tr>
  <tr>
    <td><code>iat</code></td>
    <td>always</td>
    <td>Thời gian ID token được phát hành. Được biểu thị bằng thời gian Unix (số nguyên giây). </td>
  </tr>
  <tr>
    <td><code>iss</code></td>
    <td>always</td>
    <td>Issuer Identifier cho Issuer của response. Luôn là <code>https://gid.nemoverse.io</code> cho <strong>NEMO ID</strong> ID tokens.</td>
  </tr>
  <tr>
    <td><code>sub</code></td>
    <td>always</td>
    <td>Mã định danh cho người dùng, duy nhất trong số tất cả các tài khoản <strong>NEMO ID</strong> và không bao giờ được sử dụng lại. Tài khoản <strong>NEMO ID</strong> có thể có nhiều địa chỉ email tại các thời điểm khác nhau, nhưng giá trị <code>sub</code> không bao giờ thay đổi.Sử dụng <code>sub</code> trong ứng dụng của bạn làm khóa nhận dạng duy nhất cho người dùng. Độ dài 24 ký tự chữ và số, không phân biệt chữ hoa chữ thường.</td>
  </tr>
  <tr>
    <td><code>at_hash</code></td>
    <td></td>
    <td>Access token hash. Cung cấp xác thực rằng access token được ràng buộc với ID token. Nếu ID token được cấp với <code>access_token</code> trong Authorization code flow, claim này luôn được bao gồm.</td>
  </tr>
  <tr>
    <td><code>nonce</code></td>
    <td></td>
    <td>Giá trị của <code>nonce</code> do ứng dụng của bạn cung cấp trong yêu cầu chứng thực. Bạn nên thực hiện bảo vệ chống lại các cuộc tấn công lặp lại (replay attack) bằng cách đảm bảo nó chỉ xuất hiện một lần.</td>
  </tr>
</table>

Ngoài thông tin trong ID token, bạn có thể nhận thêm [thông tin hồ sơ người dùng](#lấy-thông-tin-hồ-sơ-người-dùng) tại user profile endpoint của chúng tôi.

#### 6. Chứng thực người dùng

Sau khi lấy thông tin người dùng, bạn nên truy vấn cơ sở dữ liệu người dùng (user database) của ứng dụng của bạn.Nếu người dùng đã tồn tại trong cơ sở dữ liệu của bạn, bạn nên bắt đầu một [phiên đăng nhập ứng dụng](#application-session-local-session) cho người dùng đó nếu response của **NEMO ID** đáp ứng tất cả các yêu cầu đăng nhập.

Nếu người dùng không tồn tại trong cơ sở dữ liệu người dùng của bạn, bạn nên chuyển hướng người dùng đến quy trình đăng ký người dùng mới của mình. Bạn có thể tự động đăng ký người dùng dựa trên thông tin bạn nhận được từ **NEMO ID** hoặc ít nhất bạn có thể điền trước nhiều trường mà bạn yêu cầu trên biểu mẫu đăng ký của mình.


## Chủ đề nâng cao

### Access to private resources

Access token mà bạn nhận lại từ **NEMO ID** cho phép bạn truy cập vào các tài nguyên riêng tư, các server tài nguyên này sẽ request đến introspection endpoint để [xác thực access token](#endpoint-validate-access-token) như hình ảnh minh họa bên dưới.

****![](/public/images/access-private-resource.png)****


### Refresh token

Trong request bạn có thể yêu cầu một refresh token trả về trong quá trình [trao đổi `code`](#4-trao-đổi-code-cho-access-token-và-id-token). Một refresh token cung cấp cho ứng dụng của bạn quyền truy cập tài nguyên liên tục trong khi người dùng không có mặt trong ứng dụng của bạn. Để yêu cầu một refresh token, thêm giá trị `offline_access` vào tham số `scope` trong yêu cầu chứng thực của bạn.

Cân nhắc:

- Đảm bảo lưu trữ refresh token một cách an toàn và vĩnh viễn, vì bạn chỉ có thể nhận được refresh token vào lần đầu tiên khi bạn thực hiện quy trình trao đổi code.

- Refresh token có thể bị vô hiệu bất cứ lúc nào (do người dùng sử dụng chức năng single logout hoặc người dùng bị chặn). Trong trường hợp này, ứng dụng của bạn cần xóa trạng thái đăng nhập của người dùng và thực hiện chứng thực lại người dùng.


### Hiển thị lại consent

Bạn có thể hiển thị để người dùng ủy quyền lại ứng dụng của mình bằng cách đặt tham số `prompt` thành `consent` trong [yêu cầu xác thực](#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id) của bạn. Khi bao gồm `prompt=consent`, màn hình consent sẽ hiển thị mỗi khi ứng dụng của bạn yêu cầu cấp phép phạm vi truy cập, ngay cả khi tất cả các phạm vi trước đó đã được cấp cho ứng dụng của bạn. Vì lý do này, chỉ bao gồm `prompt=consent` khi cần thiết.

Để biết thêm về tham số `prompt`, xem `prompt` trong bảng [Authentication URI parameters](#authentication-uri-parameters).


### Tài khoản khách (Guest user)

Để thuận tiện cho việc trải nghiệm thử ứng dụng của bạn, **NEMO ID** cho phép người dùng đăng nhập dưới dạng tài khoản khách.\
Để sử dụng tính năng trên, ứng dụng của bạn cần được bật tính năng tài khoản khách. Khi đó, giao diện đăng nhập sẽ như hình dưới:

![](/public/images/guest-login.png)

Đồng thời, ứng dụng của bạn cần thêm giá trị `guest` vào tham số `scope` (tham khảo thêm tại [Scopes và Claims](#scopes-và-claims)) để có thể xác định người dùng đang đăng nhập là tài khoản khách hay tài khoản thông thường.

Ứng dụng của bạn có thể yêu cầu chuyển đổi tài khoản khách thành tài khoản thông thường bất cứ lúc nào bằng cách đặt tham số `prompt` thành `create` và `login_hint` thành giá trị claim `sub` của ID token của tài khoản khách trong [yêu cầu xác thực](#2-gửi-yêu-cầu-chứng-thực-tới-nemo-id) của bạn và thực hiện lại quy trình [Chứng thực người dùng](#chứng-thực-người-dùng).

Xem thêm ở sơ đồ bên dưới:

![](/public/images/upgrade-guest.png)


### Application session (local session)

Sau khi user đăng nhập thành công, ứng dụng nhận được bộ Token (ID Token, Access Token, Refresh Token). **Ứng dụng tiến hành tự quản lý trạng thái đăng nhập của người dùng tại ứng dụng**. Ví dụ tham khảo mô hình quản lý dưới đây:

![](/public/images/application-session.png)


### Đăng xuất và single logout

Ứng dụng thực hiện đăng xuất người dùng khỏi ứng dụng (xóa trạng thái đăng nhập) và [revoke refresh token](#endpoint-revoke-token) (trong trường hợp sử dụng).

**NEMO ID** cung cấp giải pháp single logout (remove activated token) cho khi người dùng thực hiện một số chức năng nhất định (xóa tài khoản, thay đổi mật khẩu, thay đổi thông tin email/phone, …). Vì các token đang hoạt động có thể trở nên không hợp lệ nên ứng dụng của bạn cần kiểm tra và đăng xuất người dùng trong trường hợp này. Ví dụ flow kiểm tra token và đăng xuất người dùng khỏi ứng dụng (trường hợp có sử dụng `refresh_token`):

![](/public/images/logout.png)


### Authentication URI parameters

Bảng sau đây cung cấp mô tả đầy đủ hơn về các tham số được OAuth 2.0 authentication API của **NEMO ID** chấp nhận.

<table>
  <tr>
    <th colspan="1">Parameter</th>
    <th colspan="1">Required</th>
    <th colspan="1">Description</th>
  </tr>
  <tr>
    <td><code>client_id</code></td>
    <td>(Required)</td>
    <td>Chuỗi client ID mà bạn có được khi đăng ký ứng dụng từ <a href="#thiết-lập">Thiết lập</a>.</td>
  </tr>
  <tr>
    <td><code>nonce</code></td>
    <td>(Required)</td>
    <td>Một giá trị ngẫu nhiên được tạo bởi ứng dụng của bạn để bảo vệ khỏi replay attack.</td>
  </tr>
  <tr>
    <td><code>response_type</code></td>
    <td>(Required)</td>
    <td>Giá trị OAuth 2.0 Response Type xác định luồng xử lý ủy quyền sẽ được sử dụng, bao gồm những tham số nào được trả về từ các endpoint được sử dụng. Khi sử dụng Authorization Code Flow, giá trị này là <code>code</code>.</td>
  </tr>
  <tr>
    <td><code>redirect_uri</code></td>
    <td>(Required)</td>
    <td>Xác định nơi response được gửi. Giá trị của tham số này phải khớp chính xác với một trong các giá trị chuyển hướng được ủy quyền mà bạn đã đặt tại <a href="#thiết-lập">Thiết lập</a> (bao gồm scheme HTTP hoặc HTTPS, hoa/thường và dấu '/' cuối, nếu có).</td>
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

### Xác thực ID token

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


### Lấy thông tin hồ sơ người dùng

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
