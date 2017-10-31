const createAuthToken = require('../lib/create-auth-token')

const program = require('commander')

program
  .version('1.0.0')
  .arguments('<private-key-json-file>')
  .action(function(file) {
    const key = require(file)
    const token = createAuthToken(key)
    console.log('')
    console.log('Set the "Authorization" HTTP request header to:')
    console.log('')
    console.log(token)
    console.log('')
  })

program.on('--help', function() {
  console.log('')
  console.log('Generates a Bearer token from the provided private json key file.')
  console.log('Use the output for the "Authorization" header to pass it in an HTTP request.')
})

program.parse(process.argv)
