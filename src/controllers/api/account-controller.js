import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { User } from '../../models/user.js'

/**
 * Encapsulates a controller.
 */
export class AccountController {
  /**
   * Authenticates a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const user = await User.authenticate(req.body.username, req.body.password)
      const token = Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64')

      const payload = {
        sub: user.username,
        first_name: user.firstName,
        last_name: user.lastName,
        email: user.email,
        x_permission_level: user.permissionLevel
      }

      const accessToken = jwt.sign(payload, token, {
        algorithm: 'HS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })

      // Refresh token?

      res
        .status(201)
        .json({
          access_token: accessToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error

      next(err)
    }
  }
}
