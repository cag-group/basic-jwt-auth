const { createAuthToken, authProtected } = require('../lib')

const chai = require('chai')
const chaiHttp = require('chai-http')
const assert = require('assert')
const express = require('express')

const key = require('./test-key.json')

chai.use(chaiHttp)

const fakeAccessList = {
  'test@test.com': {
    public_keys: {
      '675c7b212af1444ff67a0588939d5c0b0b7b65d3': '-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIIaiiDKGOrtdAwDQYJKoZIhvcNAQEFBQAwIDEeMBwGA1UE\nAxMVMTE3NTU4NzU4MTI5NTg0OTEzOTYxMB4XDTE3MTAyNDEyMTA1NFoXDTI3MTAy\nMjEyMTA1NFowIDEeMBwGA1UEAxMVMTE3NTU4NzU4MTI5NTg0OTEzOTYxMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlfCuLOmb4Ps0Sq8vQ2chkCOfaS6\nTpF/Dea9L3GD9vYVcHgKL/XfvkDZ7AYLLGhEO9LwfVxdtw8DhDHTuw1ijeCKzUp8\nQJ4SEUBPDJtTCWL6PXf8zYV2apUgfLLi+NiBlt45bRxLKUrt8oI6Fw6LA8JGH9zP\n4C66gSfLkCaRWJ558V7GE8x+ZcQyPX4EBNOVWr6qUAGjTFk4nomYUgCy5wNVZ42U\neDohVBEyg37mwSmCdxJo41/kxOTui6U5u4C4dLeQeoXQlrc7MlX54NTXsUNP6rQD\nJQ+9BzJd7AYf3ehGetsCLIJkMaJzC4KLrC07csAQNb4dyqsVZ/BqLYgqIwIDAQAB\nozgwNjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK\nBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAEcw5kCxxn+rTyARkQqytrylU\n+9meL3NIA0oavFudi1R4szo4C0YHmrNR0mwUbmOB6e2VLnLt8XzuE+vaia4FG2Vj\njkqmbka90wfGWO7QN7tiYg8IQmCsBI0inyyMbHaL6jCwRxwwHHZXsdSag/eU75pQ\niF8J+qxkGviPjnZGNA71nWlhitYmaDKKDEX7Wi8NIj9Yjfe144NAeHR8Z9ioL/t3\nLxY3tnj1z5neQU4PxsINca/KZsqbaMDdecsrZcT3usVGT/WNn15/91AAu+oxBOlc\nsj26Sy9fnDOqCQT9utYHbYDSwkkAaDV//P9QjXgI2GQT4uf8+9JmQuEdA9isyg==\n-----END CERTIFICATE-----\n'
    }
  }
}

describe('Auth validation', function() {
  var app

  beforeEach(function() {
    app = express()
    app.get('/', authProtected(fakeAccessList, function(req, res) {
      res.status(200).json('OK')
    }))
  })

  it('should fail when authorization is missing', function(done) {
    chai.request(app)
      .get('/')
      .end(function(err, res) {
        assert(err !== null)
        assert(res.status, 401)
        done()
      })
  })

  it('should fail when authorization is invalid', function(done) {
    chai.request(app)
      .get('/')
      .set('Authorization', 'garbage')
      .end(function(err, res) {
        assert(err !== null)
        assert.equal(res.status, 401)
        done()
      })
  })

  it('should call the handler when authorized', function(done) {
    chai.request(app)
      .get('/')
      .set('Authorization', createAuthToken(key))
      .end(function(err, res) {
        assert(err === null)
        assert.equal(res.status, 200)
        assert.equal(res.body, 'OK')
        done()
      })
  })

  it('should fail when the token is expired', function(done) {
    chai.request(app)
      .get('/')
      .set('Authorization', createAuthToken(key, Date.now() / 1000 - 11, 10))
      .end(function(err, res) {
        assert(err !== null)
        assert.equal(res.status, 401)
        done()
      })
  })
})
