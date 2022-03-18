import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import validator from 'validator'

const { isEmail } = validator

const schema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required.'],
    trim: true
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required.'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email address is required.'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [isEmail, 'Please provide a valid email address.']
  },
  username: {
    type: String,
    required: [true, 'Username is required.'],
    unique: true
  },
  password: {
    type: String,
    minLength: [10, 'The password must be of minimum length 10 characters.'],
    maxLength: [256, 'The password must be of maximum length 256 characters.'],
    required: [true, 'Password is required.']
  },
  permissionLevel: Number
}, {
  timestamps: true,
  toJSON: {
    /**
     * Removes sensitive information.
     *
     * @param {object} doc - The mongoose document which is being converted.
     * @param {object} ret - The plain object representation which has been converted.
     */
    transform: function (doc, ret) {
      delete ret._id
      delete ret.__v
    },
    virtuals: true
  }
})

schema.virtual('id').get(function () {
  return this._id.toHexString()
})

// Salts and hashes password before save.
schema.pre('save', async function () {
  this.password = await bcrypt.hash(this.password, 10)
})

/**
 * Authenticates a user.
 *
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @returns {Promise<User>} The user.
 */
schema.statics.authenticate = async function (username, password) {
  const user = await this.findOne({ username })

  if (!(await bcrypt.compare(password, user?.password))) {
    throw new Error('Incorrect username or password.')
  }
  return user
}

export const User = mongoose.model('User', schema)
