'use strict'

const Buffer = require('safe-buffer').Buffer

function getWebCrypto () {
  if (typeof window !== 'undefined') {
    // This is only a shim for interfaces, not for functionality
    require('webcrypto-shim')(window)

    if (window.crypto) {
      return window.crypto
    }
  }

  throw new Error('Please use an environment with crypto support')
}

const crypto = getWebCrypto()

module.exports = function randomBytes (length) {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error('randomBytes requires a positive integer argument')
  }
  const arr = new Uint8Array(length)
  return Buffer.from(crypto.getRandomValues(arr))
}
