'use strict'

const multihashing = require('multihashing-async')

module.exports = (keysProtobuf, randomBytes, crypto) => {
  crypto = crypto || require('./crypto')(randomBytes)

  class Secp256k1PublicKey {
    constructor (key) {
      crypto.validatePublicKey(key)
      this._key = key
    }

    async verify (data, sig) {
      return crypto.hashAndVerify(this._key, sig, data)
    }

    marshal () {
      return crypto.compressPublicKey(this._key)
    }

    get bytes () {
      return keysProtobuf.PublicKey.encode({
        Type: keysProtobuf.KeyType.Secp256k1,
        Data: this.marshal()
      })
    }

    equals (key) {
      return this.bytes.equals(key.bytes)
    }

    async hash () {
      return new Promise((resolve, reject) => {
        multihashing(this.bytes, 'sha2-256', (err, res) => {
          if (err) return reject(err)
          resolve(res)
        })
      })
    }
  }

  class Secp256k1PrivateKey {
    constructor (key, publicKey) {
      this._key = key
      this._publicKey = publicKey || crypto.computePublicKey(key)
      crypto.validatePrivateKey(this._key)
      crypto.validatePublicKey(this._publicKey)
    }

    async sign (message) {
      return crypto.hashAndSign(this._key, message)
    }

    get public () {
      return new Secp256k1PublicKey(this._publicKey)
    }

    marshal () {
      return this._key
    }

    get bytes () {
      return keysProtobuf.PrivateKey.encode({
        Type: keysProtobuf.KeyType.Secp256k1,
        Data: this.marshal()
      })
    }

    equals (key) {
      return this.bytes.equals(key.bytes)
    }

    async hash () {
      return new Promise((resolve, reject) => {
        multihashing(this.bytes, 'sha2-256', (err, res) => {
          if (err) return reject(err)
          resolve(res)
        })
      })
    }
  }

  async function unmarshalSecp256k1PrivateKey (bytes) {
    return new Secp256k1PrivateKey(bytes)
  }

  function unmarshalSecp256k1PublicKey (bytes) {
    return new Secp256k1PublicKey(bytes)
  }

  async function generateKeyPair () {
    const privateKeyBytes = await crypto.generateKey()
    return new Secp256k1PrivateKey(privateKeyBytes)
  }

  return {
    Secp256k1PublicKey,
    Secp256k1PrivateKey,
    unmarshalSecp256k1PrivateKey,
    unmarshalSecp256k1PublicKey,
    generateKeyPair
  }
}
