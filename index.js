const bufferEqual = require('buffer-equal-constant-time')
const Buffer = require('safe-buffer').Buffer
const { encode } = require('base64-arraybuffer')

const { HMAC, RSA } = require('react-native-simple-crypto')
const util = require('util')
const { stringToArrayBuffer, arrayBufferToString, arrayBufferToBuffer, bufferToArrayBuffer } = require('./bufferutils')

const MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "RS256", "RS384", "RS512" and "none".'
const MSG_INVALID_SECRET = 'secret must be a string or buffer'
const MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer'
const MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object'

function fromBase64(base64) {
  return base64
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function toBase64(base64url) {
  base64url = base64url.toString()

  var padding = 4 - base64url.length % 4
  if (padding !== 4) {
    for (var i = 0; i < padding; ++i) {
      base64url += '='
    }
  }

  return base64url
    .replace(/\-/g, '+')
    .replace(/_/g, '/')
}

function typeError(template) {
  var args = [].slice.call(arguments, 1)
  var errMsg = util.format.bind(util, template).apply(null, args)
  return new TypeError(errMsg)
}

function arrayBufferify(thing) {
  if (thing instanceof ArrayBuffer) {
    return thing
  }
  if (thing instanceof Buffer) {
    return bufferToArrayBuffer(thing)
  }
  if (typeof thing !== 'string') {
    thing = JSON.stringify(thing)
  }
  return stringToArrayBuffer(thing)
}

function stringify(thing) {
  if (typeof thing === 'string') {
    return thing
  }
  if (thing instanceof Buffer) {
    return thing.toString()
  }
  if (thing instanceof ArrayBuffer) {
    return arrayBufferToString(thing)
  }
  return JSON.stringify(thing)
}

function createHmacSigner() {
  return async function sign(thing, secret) {
    secret = arrayBufferify(secret)
    thing = arrayBufferify(thing)

    const sig = await HMAC.hmac256(thing, secret)
    return fromBase64(encode(sig))
  }
}

function createHmacVerifier(bits) {
  return async function verify(thing, signature, secret) {
    const computedSig = await createHmacSigner(bits)(thing, secret)
    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig))
  }
}

function createKeySigner(bits) {
  return async function sign(thing, privateKey) {
    privateKey = stringify(privateKey)
    thing = stringify(thing)
    const sig = await RSA.sign(thing, privateKey, 'SHA' + bits)
    return fromBase64(sig)
  }
}

function createKeyVerifier(bits) {
  return async function verify(thing, signature, publicKey) {
    thing = stringify(thing)
    signature = toBase64(signature)
    const verified = await RSA.verify(thing, signature, publicKey, 'SHA' + bits)
    return verified
  }
}

function createNoneSigner() {
  return function sign() {
    return ''
  }
}

function createNoneVerifier() {
  return function verify(thing, signature) {
    return signature === ''
  }
}

module.exports = function jwa(algorithm) {
  var signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    none: createNoneSigner,
  }
  var verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    none: createNoneVerifier,
  }
  var match = algorithm.match(/^(RS|HS)(256|384|512)$|^(none)$/i)
  if (!match)
    throw typeError(MSG_INVALID_ALGORITHM, algorithm)
  var algo = (match[1] || match[3]).toLowerCase()
  var bits = match[2]

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  }
}
