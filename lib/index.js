const authProtected = require('./auth-protected')
const { createToken, createBearerTokenString, createAuthRequestToken } = require('./fetch-with-authentication')

module.exports = {
  authProtected,
  createToken,
  createBearerTokenString
}
