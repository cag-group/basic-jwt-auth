const jwt = require('jsonwebtoken')

/**
 * Creates a JWT Bearer token string based on passed in private key and information for how long it should be valid for.
 *
 * @param {Object} key see #fetchWithAuthentication for the value of this property
 * @param {number} issuedAt Date in seconds when the token should be issued
 * @param {number} validFor Duration for how long the token will be valid
 */
function createAuthToken({ client_email: email, private_key_id: privateKeyID, private_key: privateKey }, issuedAt = Date.now(), validFor = 3600) {
  const expires = issuedAt + validFor

  const payload = {
    'iat': issuedAt,
    'exp': expires,
    'iss': email,
    'signing_key_id': privateKeyID
  }

  return `Bearer ${jwt.sign(payload, privateKey, { algorithm: 'RS256' })}`
}

module.exports = createAuthToken
