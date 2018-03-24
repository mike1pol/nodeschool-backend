const jwt = require('jsonwebtoken')

function getUserId(ctx) {
  const Authorization = ctx.request.get('Authorization')
  if (Authorization) {
    const token = Authorization.replace('Bearer ', '')
    try {
      const { userId } = jwt.verify(token, process.env.APP_SECRET)
      return userId
    } catch (e) {
      throw new AuthError()
    }
  }

  throw new AuthError()
}

class AuthError extends Error {
  constructor() {
    super('Not authorized')
  }
}

module.exports = {
  getUserId,
  AuthError
}
