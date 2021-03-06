const { getUserId } = require('../../utils')

const post = {
  async createDraft(parent, { title, text, isPublished = false }, ctx, info) {
    const userId = getUserId(ctx)
    const user = await ctx.db.exists.User({
      id: userId,
      type: "Admin"
    })
    if (!user) {
      throw new Error('Forbidden')
    }
    return ctx.db.mutation.createPost(
      {
        data: {
          title,
          text,
          isPublished,
          author: {
            connect: { id: userId },
          },
        },
      },
      info
    )
  },

  async publish(parent, { id }, ctx, info) {
    const userId = getUserId(ctx)
    const postExists = await ctx.db.exists.Post({
      id,
      author: { id: userId },
    })
    if (!postExists) {
      throw new Error(`Post not found or you're not the author`)
    }

    return ctx.db.mutation.updatePost(
      {
        where: { id },
        data: { isPublished: true },
      },
      info,
    )
  },

  async deletePost(parent, { id }, ctx, info) {
    const userId = getUserId(ctx)
    const postExists = await ctx.db.exists.Post({
      id,
      author: { id: userId },
    })
    if (!postExists) {
      throw new Error(`Post not found or you're not the author`)
    }

    return ctx.db.mutation.deletePost({ where: { id } })
  },
}

module.exports = { post }
