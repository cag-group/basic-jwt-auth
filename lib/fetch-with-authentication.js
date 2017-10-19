const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')

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
function fetchWithAuthentication(key) {
  const now = Date.now()
  const expires = now + 3600

  const payload = {
    'iat': now,
    'exp': expires,
    'iss': key.client_email,
    'signing_key_id': key.private_key_id
  }

  const token = jwt.sign(payload, key.private_key, { algorithm: 'RS256' })

  return function(url, options) {
    const authroizatedHeaders = Object.assign({}, options.headers, {
      'Authorization': `Bearer ${token}`
    })
    const authorizedOptions = Object.assign({}, options, { headers: authroizatedHeaders })

    return fetch(url, authorizedOptions)
  }
}

module.exports = fetchWithAuthentication
