const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')
const { Request } = require('node-fetch')

/**
 * Creates a JWT based on passed in private key and information for how long it should be valid for.
 *
 * @param {Object} key see #fetchWithAuthentication for the value of this property
 * @param {number} issuedAt Date in seconds when the token should be issued
 * @param {number} validFor Duration for how long the token will be valid
 */
function createToken({ client_email: email, private_key_id: privateKeyID, private_key: privateKey }, issuedAt, validFor) {
  const expires = issuedAt + validFor

  const payload = {
    'iat': issuedAt,
    'exp': expires,
    'iss': email,
    'signing_key_id': privateKeyID
  }

  return jwt.sign(payload, privateKey, { algorithm: 'RS256' })
}

/**
 * Creates a bearer token string that can be used for the Authorization header in a HTTP request.
 *
 * @param {string} token The signed token string
 */
function createBearerTokenString(token) {
  return `Bearer ${token}`
}

/**
 * Creates a request that can be used with 'node-fetch'.
 *
 * The returned Request object will have the Authorization header set with the token.
 *
 * @param {string} url
 * @param {string} token
 * @param {Object} options
 */
function createRequest(url, token, options = {}) {
  const authroizatedHeaders = Object.assign({}, options.headers, {
    'Authorization': createBearerTokenString(token)
  })
  const authorizedOptions = Object.assign({}, options, { headers: authroizatedHeaders })

  return new Request(url, authorizedOptions)
}

/**
 * Create a fetch function that will attach an authorization token based on the
 * provided key.
 *
 * The key object needs to specify `client_email`, `private_key_id` and `private_key`.
 * A private key JSON downloaded when creating a service account key in Google Cloud
 * automatically can be required and submitted without change.
 *
 * @param {Object} key the private key, see description for more information.
 */
function fetchWithAuthentication(key, issuedAt = Date.now(), validFor = 3600) {
  const authRequestString = createBearerTokenString(key, issuedAt, validFor)

  return function(url, options) {
    return fetch(createRequest(url, authRequestString, options))
  }
}

module.exports = {
  createToken,
  createBearerTokenString,
  createRequest,
  fetchWithAuthentication
}
