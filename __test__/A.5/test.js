/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.5
 */

const fs = require('fs')
const path = require('path')


const jwa = require('../../')

const input = fs.readFileSync(path.join(__dirname, 'input.txt'))

const algo = jwa('none')

describe('A.5. Example Unsecured JWS', () => {
  it('signs', async () => {
    expect(await algo.sign(input)).toEqual('')
  })
  it('verifies', async () => {
    expect(await algo.verify(input, '')).toBe(true)
  })
})
