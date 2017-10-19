const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')

function getAuthToken(req) {
  return new Promise(function(resolve, reject) {
    const authHeader = req.get('Authorization')
    if (authHeader === undefined) {
      reject(new Error('No authorization header'))
    }

    if (authHeader.slice(0, 7) !== 'Bearer ') {
      reject(new Error('Malformed authorization header'))
    }
    resolve(authHeader.slice('Bearer '.length))
  })
}

function getPublicKeyURL(accessList, issuer) {
  return accessList[issuer].public_keys_url
}

function issuerInAccessList(accessList, issuer) {
  return issuer in accessList
}

function authenticateAndAuthorize(token, accessList) {
  const decodedToken = jwt.decode(token)
  const issuer = decodedToken.iss

  return new Promise(function(resolve, reject) {
    if (!issuerInAccessList(accessList, issuer)) {
      reject(new Error('Token issuer not authorized'))
    }

    const keyURL = getPublicKeyURL(accessList, issuer)
    fetch(keyURL)
      .then(function(response) { return response.json() })
      .then(function(keys) {
        try {
          const publicKey = keys[decodedToken.signing_key_id]
          const decoded = jwt.verify(token, publicKey)
          resolve(decoded)
        } catch (err) {
          reject(new Error('Token is invalid'))
        }
      })
  })
}

/**
 * Used to wrap an HTTP request handler to verify that the request is authenticated and authorized.
 *
 * Returns a new HTTP request handler that will call `handler` if the request is valid, otherwise
 * send a 401 error code back.
 *
 * The accessList is a map from email to an Object containing public_keys_url.
 *
 * @param {Object} accessList A mapping of valid issuers and URL to load the public keys used by the issuer.
 * @param {Function} handler A normal http request handler taking Request and Result.
 */
function authProtected(accessList, handler) {
  return function(req, res) {
    getAuthToken(req)
      .then(function(token) {
        return authenticateAndAuthorize(token, accessList)
      })
      .then(function() {
        handler(req, res)
      })
      .catch(function(error) {
        console.log('AUTH FAILED CATCHED')
        res.status(401).json(error.message)
      })
  }
}

module.exports = authProtected
