const createAuthToken = require('../lib/create-auth-token')
const assert = require('assert')
const jwt = require('jsonwebtoken')
const key = require('./test-key.json')

describe('Token creation', function() {
  it('should create a Bearer token', function() {
    const token = createAuthToken(key)
    assert.equal(token.slice(0, 7), 'Bearer ')
  })

  it('should create a token with the correct payload keys', function() {
    const now = Date.now()
    const token = createAuthToken(key, now, 3600)
    const decodedToken = jwt.decode(token.slice(7))
    assert.equal(decodedToken.iss, 'test@test.com')
    assert.equal(decodedToken.signing_key_id, '675c7b212af1444ff67a0588939d5c0b0b7b65d3')
    assert.equal(decodedToken.iat, now)
    assert.equal(decodedToken.exp, now + 3600)
  })
})
