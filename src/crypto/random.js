'use strict'

const crypto = require('crypto')

module.exports = function randomBytes (length) {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error('randomBytes requires a positive integer argument')
  }
  return crypto.randomBytes(length)
}
