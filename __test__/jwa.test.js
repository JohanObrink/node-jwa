const jwa = require('..')
const { promisify } = require('util')
const { generateKeyPair } = require('crypto')
const BIT_DEPTHS = ['256', '384', '512']

describe('react-native-jwa', () => {
  let key, wrongKey
  beforeAll(async () => {
    key = await promisify(generateKeyPair)('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    })
    wrongKey = await promisify(generateKeyPair)('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    })
  })

  it('HMAC256 signing, verifying', async () => {
    const input = 'eugene mirman'
    const secret = 'shhhhhhhhhh'
    const algo = jwa('hs256')
    const sig = await algo.sign(input, secret)
    expect(await algo.verify(input, sig, secret)).toBe(true)
    expect(await algo.verify(input, 'other sig', secret)).toBe(false)
    expect(await algo.verify(input, sig, 'incrorect')).toBe(false)
  })

  BIT_DEPTHS.forEach((bits) => {
    it(`RSA${bits} signing, verifying`, async () => {
      const input = 'h. jon benjamin'
      const algo = jwa('rs'+bits)
      const sig = await algo.sign(input, key.privateKey)
      expect(await algo.verify(input, sig, key.publicKey)).toBe(true)
      expect(await algo.verify(input, sig, wrongKey.publicKey)).toBe(false)
    })
  })

  it('jwa: none', async () => {
    const input = 'whatever'
    const algo = jwa('none')
    const sig = await algo.sign(input)
    expect(await algo.verify(input, sig)).toBe(true)
    expect(await algo.verify(input, 'something')).toBe(false)
  })

  it('jwa: some garbage algorithm', async () => {
    expect(() => jwa('something bogus')).toThrow()
  })

  it(`jwa: superstring of other algorithm (ahs256b)`, async () => {
    expect(() => jwa('ahs256b')).toThrow()
  })
  
  it(`jwa: partial string of other algorithm (rs)`, async () => {
    expect(() => jwa('rs')).toThrow()
  })

  it('jwa: hs512, missing secret', async () => {
    const algo = jwa('hs512')
    await expect(algo.sign('some stuff')).rejects.toThrow()
  })

  it('jwa: hs512, weird input type', async () => {
    const algo = jwa('hs512')
    const input = {a: ['whatever', 'this', 'is']}
    const secret = 'bones'
    const sig = await algo.sign(input, secret)
    expect(await algo.verify(input, sig, secret)).toBe(true)
    expect(await algo.verify(input, sig, 'other thing')).toBe(false)
  })

  it('jwa: rs512, weird input type', async () => {
    const algo = jwa('rs512')
    const input = { a: ['whatever', 'this', 'is'] }
    const sig = await algo.sign(input, key.privateKey)
    expect(await algo.verify(input, sig, key.publicKey)).toBe(true)
    expect(await algo.verify(input, sig, wrongKey.publicKey)).toBe(false)
  })

  it('jwa: rs512, missing signing key', async () => {
    const algo = jwa('rs512')
    await expect(algo.sign('some stuff')).rejects.toThrow()
  })

  it('jwa: rs512, missing verifying key', async () => {
    const algo = jwa('rs512')
    const input = { a: ['whatever', 'this', 'is'] }
    const sig = await algo.sign(input, key.privateKey)
    await expect(algo.verify(input, sig)).rejects.toThrow()
  })

})
