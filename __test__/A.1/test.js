/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.1
 */

const fs = require('fs')
const path = require('path')

const Buffer = require('safe-buffer').Buffer

const jwa = require('../../')

const input = fs.readFileSync(path.join(__dirname, 'input.txt'))
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')))

const key = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8')).k, 'base64')

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii')
const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')))

const { bufferToArrayBuffer } = require('../../bufferutils')

const algo = jwa('hs256')

describe('A.1. Example JWS Using HMAC SHA-256', () => {
  it('check fixtures', () => {
    expect(input).toEqual(inputFromBytes)
    expect(Buffer.from(signature, 'base64')).toEqual(signatureFromBytes)
  })
  it('signs', async () => {
      expect(await algo.sign(bufferToArrayBuffer(input), key)).toEqual(signature)
      expect(await algo.sign(input.toString('ascii'), key)).toEqual(signature)
  })
  it('verifies', async () => {
    expect(await algo.verify(bufferToArrayBuffer(input), signature, key)).toBe(true)
    expect(await algo.verify(input.toString('ascii'), signature, key)).toBe(true)
  })
})
