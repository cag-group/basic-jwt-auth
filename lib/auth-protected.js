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

// Returns a promise that will resolves to the decoded token if it's valid
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
