/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.2
 */

const fs = require('fs')
const path = require('path')

const Buffer = require('safe-buffer').Buffer
const jwkToPem = require('jwk-to-pem')

const jwa = require('../../')

const input = fs.readFileSync(path.join(__dirname, 'input.txt'))
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')))

const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'))
const privKey = jwkToPem(jwk, { private: true })
const pubKey = jwkToPem(jwk)

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii')
const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')))

const { bufferToArrayBuffer } = require('../../bufferutils')

const algo = jwa('rs256')

describe('A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256', () => {
  it('check fixtures', () => {
    expect(input).toEqual(inputFromBytes)
    expect(Buffer.from(signature, 'base64')).toEqual(signatureFromBytes)
  })
  it('signs', async () => {
    expect(await algo.sign(bufferToArrayBuffer(input), privKey)).toEqual(signature)
    expect(await algo.sign(input.toString('ascii'), privKey)).toEqual(signature)
  })
  it('verifies', async () => {
    expect(await algo.verify(bufferToArrayBuffer(input), signature, pubKey)).toBe(true)
    expect(await algo.verify(input.toString('ascii'), signature, pubKey)).toBe(true)
  })
})
