import jwt, { Jwt, Algorithm, JwtPayload } from 'jsonwebtoken'
import * as express from 'express'
import axios from 'axios'
import { JSONWebKey } from 'jwks-rsa'
import jwkToPem from 'jwk-to-pem'

// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
// https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/jsonwebtoken/index.d.ts#L121
declare module 'express' {
  interface Request {
    user?: JwtPayload
  }
}

export interface Options {
  issuer: string
  audience: string
  algorithms: Algorithm[]
}

const Authorize =
  (options: Options) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ): Promise<void | express.Response> => {
    try {
      // get Token. Remove Barer prefix
      const tokenBarer = req.headers?.authorization?.replace('Barer', '')
      // Decode token. We need the token for get KID param
      const decodedToken = jwt.decode(tokenBarer, {
        complete: true,
        json: true,
      })
      // get all KEYS by the MOCK (Defined in index.spec.ts)
      const keys: [JSONWebKey] = (
        await axios.get(`${options.issuer}/.well-known/jwks.json`)
      ).data.keys
      // Get KID
      const kid = decodedToken?.header?.kid
      // Find the KID in the list of the KEYS. This is the PK
      const PK = keys.find((key) => key.kid == kid)
      // Transform PK (Public Key). JWT to PEM
      // https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
      const pemToken = jwkToPem(PK)
      // User verified
      const verified = await jwt.verify(tokenBarer, pemToken, {
        algorithms: options.algorithms,
        audience: options.audience,
        issuer: options.issuer,
      } as jwt.VerifyOptions)
      // Force to send in the Request[user]
      req.user = verified as JwtPayload
      next()
    } catch (error) {
      res.sendStatus(401)
    }
  }
export default Authorize
