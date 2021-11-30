import nock from 'nock'
import { createRequest, createResponse } from 'node-mocks-http'
import Authorise from './index'
import TokenGenerator from './__tests__/TokenGenerator'
import { Algorithm } from 'jsonwebtoken'
import axios from 'axios'

const tokenGenerator = new TokenGenerator()
const options = {
  issuer: 'http://issuer.com',
  audience: 'audience',
  algorithms: ['RS256' as Algorithm],
}
const currentTime = Math.round(Date.now() / 1000)
const claims = {
  sub: 'foo',
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
}

// https://github.com/nock/nock#axios
axios.defaults.adapter = require('axios/lib/adapters/http')

beforeAll(async () => {
  await tokenGenerator.init()

  nock(options.issuer)
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, { keys: [tokenGenerator.jwk] })
})

describe('A request with a valid access token', () => {
  test('should add a user object containing the token claims to the request', async () => {
    const res = createResponse()
    const next = jest.fn()
    const token = await tokenGenerator.createSignedJWT(claims)
    const req = createRequest({
      headers: {
        // Modified. authorizationinfo is not a standard header
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
        authorization: token,
      },
    })

    await Authorise(options)(req, res, next)
    expect(req).toHaveProperty('user', claims)
  })
})
