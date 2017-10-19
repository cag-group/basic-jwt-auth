const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')

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
