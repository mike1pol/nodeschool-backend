const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { getUserId } = require('../../utils')

const auth = {
  async signup(parent, args, ctx, info) {
    const password = await bcrypt.hash(args.password, 10)
    const user = await ctx.db.mutation.createUser({
      data: { ...args, password, type: "Guest" },
    })

    return {
      token: jwt.sign({ userId: user.id }, process.env.APP_SECRET),
      user,
    }
  },

  async login(parent, { email, password }, ctx, info) {
    const user = await ctx.db.query.user({ where: { email } })
    if (!user) {
      throw new Error(`No such user found for email: ${email}`)
    }

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      throw new Error('Invalid password')
    }

    return {
      token: jwt.sign({ userId: user.id }, process.env.APP_SECRET),
      user,
    }
  },

  async changePassword(parent, { oldPassword, newPassword }, ctx, info) {
    const userId = getUserId(ctx)

    const user = await ctx.db.query.user({ where: { id: userId } })
    if (!user) {
      throw new Error(`No current user found`)
    }

    const matches = await bcrypt.compare(oldPassword, user.password)
    if (!matches) {
      throw new Error('Old password doesn\'t match')
    }

    const password = await bcrypt.hash(newPassword, 10);

    const updatedUser = await ctx.db.mutation.updateUser({data: {password}, where: {id: userId}}, info)
    return updatedUser;
  }
}

module.exports = { auth }
