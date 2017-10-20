const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')
const { Request } = require('node-fetch')

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

function createRequest(url, token, options = {}) {
  const authroizatedHeaders = Object.assign({}, options.headers, {
    'Authorization': `Bearer ${token}`
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
  const token = createToken(key, issuedAt, validFor)

  return function(url, options) {
    return fetch(createRequest(url, token, options))
  }
}

module.exports = {
  createToken,
  createRequest,
  fetchWithAuthentication
}
