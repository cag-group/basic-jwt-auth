const { createToken, createRequest } = require('../lib/fetch-with-authentication')
const assert = require('assert')
const jwt = require('jsonwebtoken')
const key = require('./test-key.json')

describe('Client', function() {
  it('should create a token with the correct payload keys', function() {
    const now = Date.now()
    const token = createToken(key, now, 3600)
    const decodedToken = jwt.decode(token)
    assert.equal(decodedToken.iss, 'test@test.com')
    assert.equal(decodedToken.signing_key_id, '689d4337c06af302a098d3b80cbf7c2b5f12b42e')
    assert.equal(decodedToken.iat, now)
    assert.equal(decodedToken.exp, now + 3600)
  })

  it('should set the authorization header on requests', function() {
    const token = 'testtokenstring'
    const request = createRequest('http://test.com', token, {})
    assert.equal(request.headers.get('Authorization'), 'Bearer testtokenstring')
    assert(request.headers.get('content-type') === null)
  })

  it('should merge the authorization header with other request headers', function() {
    const token = 'testtokenstring'
    const request = createRequest('http://test.com', token, {'headers': { 'content-type': 'application/json' }})
    assert.equal(request.headers.get('Authorization'), 'Bearer testtokenstring')
    assert.equal(request.headers.get('content-type'), 'application/json')
  })
})
