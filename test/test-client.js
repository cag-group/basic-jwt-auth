const createAuthToken = require('../lib/create-auth-token')
const assert = require('assert')
const jwt = require('jsonwebtoken')
const key = require('./test-key.json')

describe('Client', function() {
  it('should create a token with the correct payload keys', function() {
    const now = Date.now()
    const token = createAuthToken(key, now, 3600)
    const decodedToken = jwt.decode(token.slice(7))
    assert.equal(decodedToken.iss, 'test@test.com')
    assert.equal(decodedToken.signing_key_id, '689d4337c06af302a098d3b80cbf7c2b5f12b42e')
    assert.equal(decodedToken.iat, now)
    assert.equal(decodedToken.exp, now + 3600)
  })
})
