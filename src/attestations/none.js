// None Attestation Statement Format
// https://www.w3.org/TR/webauthn/#none-attestation

const attestation = {
  name: 'none',
  verifyAttestation: () => {},
  verifyAssertion: () => {}
}

module.exports = attestation