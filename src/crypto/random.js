'use strict'

const crypto = require('crypto')

module.exports = function getRandomValues (arr) {
  return crypto.randomBytes(arr.length)
}
