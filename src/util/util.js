const crypto = require('crypto')
const cbor = require('cbor')

const sha256 = (data) => {
  const hash = crypto.createHash('sha256')
  hash.update(data)
  return hash.digest()
}

const unparseUUID = (bytes) => {
  const hexString = Buffer.from(bytes).toString('hex')
  return [
    hexString.slice(0, 8),
    hexString.slice(8, 12),
    hexString.slice(12, 16),
    hexString.slice(16, 20),
    hexString.slice(20),
  ].join('-')
}

const coseToJwk = (cose) => {
  try {
    let publicKeyJwk = {}
    const publicKeyCbor = cbor.decodeFirstSync(cose)

    if (publicKeyCbor.get(3) == -7) {
      publicKeyJwk = {
        kty: 'EC',
        crv: 'P-256',
        x: publicKeyCbor.get(-2).toString('base64'),
        y: publicKeyCbor.get(-3).toString('base64'),
      }
    } else if (publicKeyCbor.get(3) == -257) {
      publicKeyJwk = {
        kty: 'RSA',
        n: publicKeyCbor.get(-1).toString('base64'),
        e: publicKeyCbor.get(-2).toString('base64'),
      }
    } else {
      throw new Error('Unknown public key algorithm')
    }

    return publicKeyJwk
  } catch (e) {
    // console.log(e)
    throw new Error('Could not decode COSE Key')
  }
}

module.exports = { sha256, unparseUUID, coseToJwk }