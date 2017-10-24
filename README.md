# Basic JWT Auth
This is a small framework to act as a replacement for basic authentication when
implementation authentication between microservices.

While there is nothing Google specific required to use the library, it's mainly built as a
way to make it easy to authenticate services running in Google Cloud with service accounts
set up.

## Usage in Google Cloud
### Setup
1. Setup a service account with a JSON private key for the calling service.
2. Make the private key available to the calling service, the best way to do this depends on where the service is running.
3. Note the `client_email` and `client_x509_cert_url` from the private key and added it to the access_list of the service that requires authentication.

### Server

#### function.js
```javascript
const ACCESS_LIST = require('./access_list.json')

exports.authtest = authProtected(ACCESS_LIST, function(req, res) {
  // Handle as normally
}
```

#### access_list.json
```json
{
  "[SERVICE_ACCOUNT_EMAIL]": {
    "public_keys_url": "https://www.googleapis.com/robot/v1/metadata/x509/[SERVICE_ACCOUNT_EMAIL]"
  }
}
```

### Client

#### client.js
```javascript
  const { createAuthToken } = require('@cag-group/basic-jwt-auth')
  // With node-fetch
  const fetch = require('node-fetch')

  // A private key as downloaded when generating a service account key
  const key = require('private-key.json')

  // Create a bearer token 'Bearer 12d1d...'
  const authToken = createAuthToken(key)

  // returns a promise with the result
  fetch('https://auth-protected-url', { headers: { 'Authorization': authToken }})
```

#### private-key.json
```json
{
  "type": "service_account",
  "project_id": "[PROJECT_ID]",
  "private_key_id": "[PROJECT_KEY_ID]",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...-----END PRIVATE KEY-----\n",
  "client_email": "[SERVICE_ACCOUNT_EMAIL]",
  "client_id": "[CLIENT_ID]",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/[SERVICE_ACCOUNT_EMAIL]"
}
```

