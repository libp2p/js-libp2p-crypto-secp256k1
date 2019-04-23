'use strict'

const bs58 = require('bs58')
const multihashing = require('multihashing-async')
const { composePrivateKey, decomposePrivateKey } = require('crypto-key-composer')

module.exports = (keysProtobuf, randomBytes, crypto) => {
  crypto = crypto || require('./crypto')(randomBytes)

  class Secp256k1PublicKey {
    constructor (key) {
      crypto.validatePublicKey(key)
      this._key = key
    }

    verify (data, sig, callback) {
      ensure(callback)
      crypto.hashAndVerify(this._key, sig, data, callback)
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

    hash (callback) {
      ensure(callback)
      multihashing(this.bytes, 'sha2-256', callback)
    }
  }

  class Secp256k1PrivateKey {
    constructor (key, publicKey) {
      this._key = key
      this._publicKey = publicKey || crypto.computePublicKey(key)
      crypto.validatePrivateKey(this._key)
      crypto.validatePublicKey(this._publicKey)
    }

    sign (message, callback) {
      ensure(callback)
      crypto.hashAndSign(this._key, message, callback)
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

    hash (callback) {
      ensure(callback)
      multihashing(this.bytes, 'sha2-256', callback)
    }

    /**
     * Gets the ID of the key.
     *
     * The key id is the base58 encoding of the SHA-256 multihash of its public key.
     * The public key is a protobuf encoding containing a type and the DER encoding
     * of the PKCS SubjectPublicKeyInfo.
     *
     * @param {function(Error, id)} callback
     * @returns {undefined}
     */
    id (callback) {
      this.public.hash((err, hash) => {
        if (err) {
          return callback(err)
        }
        callback(null, bs58.encode(hash))
      })
    }

    /**
     * Exports the key into a password protected PEM format
     *
     * @param {string} [format] - Defaults to 'pkcs-8'.
     * @param {string} password - The password to read the encrypted PEM
     * @param {function(Error, KeyInfo)} callback
     * @returns {undefined}
     */
    export (format, password, callback) {
      if (typeof password === 'function') {
        callback = password
        password = format
        format = 'pkcs-8'
      }

      ensure(callback)

      let err = null
      let pem = null

      const decompressedPublicKey = typedArrayToUint8Array(crypto.decompressPublicKey(this.public._key))
      try {
        if (format === 'pkcs-8') {
          pem = composePrivateKey({
            format: 'pkcs8-pem',
            keyAlgorithm: {
              id: 'ec-public-key',
              namedCurve: 'secp256k1'
            },
            keyData: {
              d: typedArrayToUint8Array(this.marshal()),
              // The public key concatenates the x and y values and adds an initial byte
              x: decompressedPublicKey.slice(1, 33),
              y: decompressedPublicKey.slice(33, 65)
            },
            encryptionAlgorithm: {
              keyDerivationFunc: {
                id: 'pbkdf2',
                iterationCount: 10000, // The number of iterations
                keyLength: 32, // Automatic, based on the `encryptionScheme`
                prf: 'hmac-with-sha512' // The pseudo-random function
              },
              encryptionScheme: {
                id: 'aes256-cbc'
              }
            }
          }, { password })
        } else {
          err = new Error(`Unknown export format '${format}'`)
        }
      } catch (_err) {
        err = _err
      }

      callback(err, pem)
    }
  }

  function unmarshalSecp256k1PrivateKey (bytes, callback) {
    callback(null, new Secp256k1PrivateKey(bytes), null)
  }

  function unmarshalSecp256k1PublicKey (bytes) {
    return new Secp256k1PublicKey(bytes)
  }

  function generateKeyPair (_bits, callback) {
    if (callback === undefined && typeof _bits === 'function') {
      callback = _bits
    }

    ensure(callback)

    crypto.generateKey((err, privateKeyBytes) => {
      if (err) { return callback(err) }

      let privkey
      try {
        privkey = new Secp256k1PrivateKey(privateKeyBytes)
      } catch (err) { return callback(err) }

      callback(null, privkey)
    })
  }

  function importPEM (pem, password, callback) {
    let privkey
    try {
      const decomposedPrivateKey = decomposePrivateKey(pem, { password })
      privkey = new Secp256k1PrivateKey(Buffer.from(decomposedPrivateKey.keyData.d))
    } catch (err) { return callback(err) }

    callback(null, privkey)
  }

  function ensure (callback) {
    if (typeof callback !== 'function') {
      throw new Error('callback is required')
    }
  }

  function typedArrayToUint8Array (typedArray) {
    return new Uint8Array(typedArray.buffer.slice(typedArray.byteOffset, typedArray.byteOffset + typedArray.byteLength))
  }

  return {
    Secp256k1PublicKey,
    Secp256k1PrivateKey,
    unmarshalSecp256k1PrivateKey,
    unmarshalSecp256k1PublicKey,
    generateKeyPair,
    import: importPEM
  }
}
