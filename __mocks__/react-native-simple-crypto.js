const { createHash, createHmac, createSign, createVerify, generateKeyPair } = require('crypto')
const { promisify } = require('util')
const { arrayBufferToBuffer, bufferToArrayBuffer } = require('../bufferutils')

const AES = {}
const SHA = {
  sha1: async (text) => bufferToArrayBuffer(createHash('SHA1').update(text).digest()),
  sha256: async (text) => bufferToArrayBuffer(createHash('SHA256').update(text).digest()),
  sha512: async (text) => bufferToArrayBuffer(createHash('SHA512').update(text).digest())
}
const HMAC = {
  hmac256: async (text, key) => bufferToArrayBuffer(createHmac('SHA256', arrayBufferToBuffer(key)).update(arrayBufferToBuffer(text)).digest())
}
const PBKDF2 = {}
const RSA = {
  generateKeys: async (keySize) => {
    const { publicKey, privateKey } = await promisify(generateKeyPair)('rsa', {
      modulusLength: keySize,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      }
    })
    return { public: publicKey, private: privateKey }
  },
  sign: async (data, key, hash) => createSign(hash).update(data).sign(key, 'base64'),
  verify: async(data, secretToVerify, key, hash) => createVerify(hash).update(data).verify(key, secretToVerify, 'base64')
}
const utils = {}

module.exports = {
  AES,
  SHA,
  HMAC,
  PBKDF2,
  RSA,
  utils
}
