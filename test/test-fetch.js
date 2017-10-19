const { createToken } = require('../lib/fetch-with-authentication')
const assert = require('assert')
const jwt = require('jsonwebtoken')
const key = require('./test-key.json')

describe('Token creation', function() {
  it('should set required payload keys', function() {
    const now = Date.now()
    const token = createToken(key, now, 3600)
    const decodedToken = jwt.decode(token)
    assert(decodedToken.iss === 'test@test.com')
    assert(decodedToken.signing_key_id === '689d4337c06af302a098d3b80cbf7c2b5f12b42e')
    assert(decodedToken.iat === now)
    assert(decodedToken.exp === now + 3600)
  })
})
