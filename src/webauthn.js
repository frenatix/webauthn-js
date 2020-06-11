const url = require('url')
const cbor = require('cbor')
const jwkToPem = require('jwk-to-pem')
const crypto = require('crypto')
const { sha256, unparseUUID, coseToJwk } = require('./util/util')

// Global map of registered attestation formats
// https://www.w3.org/TR/webauthn/#defined-attestation-formats
const attestationMap = {}

// Register attestations
const registerAttestation = (attestationFormat) => {
  attestationMap[attestationFormat.name] = attestationFormat
}

// add attestation statement format "none"
registerAttestation(require('./attestations/none'))

/**
 * Register a new credential from client.
 *
 * https://www.w3.org/TR/webauthn/#registering-a-new-credential
 */
const registerNewCredential = ({
  response,
  expectedChallenge,
  expectedHostname,
  isValidCredentialId,
  saveUserCredential,
  showWarning = true
}) => {
  if (!response.attestationObject) {
    throw new Error('Property "attestationObject" is missing')
  }
  if (!response.clientDataJSON) {
    throw new Error('Property "clientDataJSON" is missing')
  }
  if (!expectedChallenge) {
    throw new Error('Parameter "expectedChallenge" is missing')
  }
  if (!expectedHostname) {
    throw new Error('Parameter "expectedHostname" is missing')
  }
  if (!isValidCredentialId) {
    throw new Error('Parameter "checkCredentialId" is missing')
  }
  if (!(isValidCredentialId instanceof Function)) {
    throw new Error('Parameter "checkCredentialId" must be a function')
  }
  if (!saveUserCredential) {
    throw new Error('Parameter "saveUserCredential" is missing')
  }
  if (!(saveUserCredential instanceof Function)) {
    throw new Error('Parameter "saveUserCredential" must be a function')
  }

  // Step 1: Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
  const JSONtext = response.clientDataJSON

  // Step 2: Let C, the client data claimed as collected during the credential creation, be the result of
  // running an implementation-specific JSON parser on JSONtext.
  let C
  try {
    C = JSON.parse(JSONtext)
  } catch (e) {
    throw new Error('Property "clientDataJSON" could not be parsed')
  }

  // Step 3: Verify that the value of C.type is webauthn.create.
  if (C.type !== 'webauthn.create') {
    throw new Error('The value of property "clientDataJSON.type" is not "webauthn.create"')
  }

  // Step 4: Verify that the value of C.challenge matches the challenge that was sent to the authenticator
  // in the create() call.
  if (!C.challenge) {
    throw new Error('Property "clientDataJSON.challenge" is missing')
  }
  const _expectedChallenge = retrieveValue(expectedChallenge)
  if (C.challenge !== _expectedChallenge) {
    throw new Error(`Invalid value in "cliengDataJSON.challenge". Expected challenge "${_expectedChallenge}"`)
  }

  // Step 5: Verify that the value of C.origin matches the Relying Party's origin.
  const _expectedHostname = retrieveValue(expectedHostname)
  checkOrigin(C.origin, _expectedHostname)

  // Step 6: Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
  // over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
  // C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
  if (C.tokenBinding) {
    if (showWarning) {
      console.warn('WARN: Verification of Token Binding is not implemented')
    }
  }

  // Step 7: Compute the hash of response.clientDataJSON using SHA-256.
  const clientDataHash = sha256(JSONtext) // may be used in step 14

  // Step 8: Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
  // structure to obtain the attestation statement format fmt, the authenticator data authData, and the
  // attestation statement attStmt.
  let attestationObject
  try {
    attestationObject = cbor.decodeFirstSync(Buffer.from(response.attestationObject, 'base64'))
  } catch (e) {
    throw new Error('Property "attestationObject" could not be decoded')
  }

  let authenticatorData
  try {
    authenticatorData = parseAuthenticatorData(attestationObject.authData)
  } catch (e) {
    const error = new Error('The value of "attestationObject.authData" could not be parsed')
    error.stack = e.stack
    throw error
  }

  // Step 9: Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
  const expectedRpIdHash = sha256(_expectedHostname)
  if (!authenticatorData.rpIdHash.equals(expectedRpIdHash)) {
    throw new Error(`The value of "attestationObject.authData.rpIdHash" is wrong. Expected hash "${expectedRpIdHash}"`)
  }

  // Step 10: Verify that the User Present bit of the flags in authData is set.
  if ((authenticatorData.flags & 0b00000001) === 0) {
    throw new Error('User Present bit was not set in "attestationObject.authData.flags"')
  }

  // Step 11: If user verification is required for this registration, verify that the User
  // Verified bit of the flags in authData is set.
  if ((authenticatorData.flags & 0b00000100) == 0) {
    throw new Error('User Verified bit was not set in "attestationObject.authData.flags"')
  }

  // Step 12: Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
  // extension outputs in the extensions in authData are as expected, considering the client extension input values
  // that were given as the extensions option in the create() call.

  // Step 13: Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against
  // the set of supported WebAuthn Attestation Statement Format Identifier values.
  if (!Object.keys(attestationMap).includes(attestationObject.fmt)) {
    throw new Error(`Attestation statement format not supported: ${attestationObject.fmt}`)
  }

  // Step 14: Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by
  // using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the
  // serialized client data computed in step 7.
  const attestationStmtFormat = attestationMap[attestationObject.fmt]
  try {
    attestationStmtFormat.verifyAttestation(attestationObject, clientDataHash)
  } catch (e) {
    throw e
  }

  // Step 15: If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates
  // or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted
  // source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain
  // such information, using the aaguid in the attestedCredentialData in authData.
  // => not implemented

  // Step 16: Assess the attestation trustworthiness using the outputs of the verification procedure in step 14.
  // => ok until here

  // Step 17: Check that the credentialId is not yet registered to any other user. If registration is requested
  // for a credential that is already registered to a different user, the Relying Party SHOULD fail this
  // registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
  if (!isValidCredentialId(authenticatorData.credentialId)) {
    throw new Error('CredentialId is not allowed')
  }

  // Step 18: If the attestation statement attStmt verified successfully and is found to be trustworthy, then register
  // the new credential with the account that was denoted in the options.user passed to create(), by associating it
  // with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the
  // Relying Party's system.
  const credential = {
    id: authenticatorData.attestedCredentialData.credentialId.toString('base64'),
    publicKeyJwk: authenticatorData.attestedCredentialData.publicKeyJwk,
    signCount: authenticatorData.signCount
  }
  if (saveUserCredential) {
    try {
      saveUserCredential(credential)
    } catch (e) {
      throw e
    }
  }

  // Step 19: If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above,
  // the Relying Party SHOULD fail the registration ceremony.

  return credential
}

const retrieveValue = (stringOrFunction) => {
  let value
  if (stringOrFunction instanceof Function) {
    value = stringOrFunction()
  } else {
    value = stringOrFunction
  }
  if (typeof value !== 'string') {
    throw new Error('Parameter is not valid')
  }
  return value
}

const checkOrigin = (originValue, expectedHostname) => {
  let origin
  try {
    origin = url.parse(originValue)
  } catch (e) {
    throw new Error('The value of property "clientDataJSON.origin" could not be parsed')
  }

  if (origin.hostname !== expectedHostname) {
    throw new Error(`Invalid value in property "clientDataJSON.origin". Expected hostname "${expectedHostname}"`)
  }

  if (origin.hostname !== 'localhost' && origin.protocol !== 'https:') {
    throw new Error('Invalid value in property "clientDataJSON.origin". Expected HTTPS protocol.')
  }
}

// Parse AuthenticatorData
// https://www.w3.org/TR/webauthn/#sec-authenticator-data
const parseAuthenticatorData = (authData) => {
  const authenticatorData = {}

  // rpIdHash (32 bytes): SHA-256 hash of the RP ID the credential is scoped to.
  authenticatorData.rpIdHash = authData.slice(0, 32)

  // flags (1 byte): bit 0 is the least significant bit
  // Bit 0: User Present
  // Bit 2: User Verified
  // Bit 6: Attested credential data
  // Bit 7: Extension data included
  authenticatorData.flags = authData[32]

  // If extension flag is set, then we abort.
  // We can't determine the length of Attested Credential Data reliably.
  // see https://stackoverflow.com/questions/54045911/webauthn-byte-length-of-the-credential-public-key
  if (authenticatorData.flags & 0b10000000) {
    throw new Error('Extension Data is included. Not supported by this lib.')
  }

  // signCount (4 bytes): Signature counter, 32-bit unsigned big-endian integer.
  authenticatorData.signCount = new DataView(new Uint8Array(authData.slice(33, 37)).buffer).getInt32(0, false)

  // attested credential data (if present)
  // Bit 6 is set
  if (authenticatorData.flags & 0b01000000) {
    // https://www.w3.org/TR/webauthn/#sec-attested-credential-data
    const attestedCredentialData = {}

    // The AAGUID of the authenticator.
    attestedCredentialData.aaguid = unparseUUID(authData.slice(37, 53))

    // Byte length of Credential ID, 16-bit unsigned big-endian integer.
    attestedCredentialData.credentialIdLength = new DataView(new Uint8Array(authData.slice(53, 55)).buffer).getInt16(
      0,
      false
    )

    // Credential ID
    attestedCredentialData.credentialId = authData.slice(55, 55 + attestedCredentialData.credentialIdLength)

    // The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC8152], using the CTAP2
    // canonical CBOR encoding form.
    const publicKeyCoseBuffer = authData.slice(55 + attestedCredentialData.credentialIdLength, authData.length)

    // convert public key to JWK
    attestedCredentialData.publicKeyJwk = coseToJwk(publicKeyCoseBuffer)

    // assign
    authenticatorData.attestedCredentialData = attestedCredentialData
  }

  // No extensions handling

  return authenticatorData
}

/**
 * Verify an assertion.
 *
 * https://www.w3.org/TR/webauthn/#verifying-assertion
 */
const verifyAssertion = ({
  response,
  credential,
  expectedChallenge,
  expectedHostname,
  isAllowedCredentialId,
  updateSignCount
}) => {
  // Validation
  if (!response.id) {
    throw new Error('Property "id" is missing')
  }
  if (!response.clientDataJSON) {
    throw new Error('Property "clientDataJSON" is missing')
  }
  if (!response.signature) {
    throw new Error('Property "signature" is missing')
  }
  if (!response.authenticatorData) {
    throw new Error('Property "authenticatorData" is missing')
  }
  if (!expectedChallenge) {
    throw new Error('Parameter "expectedChallenge" is missing')
  }
  if (!expectedHostname) {
    throw new Error('Parameter "expectedHostname" is missing')
  }

  // Step 1: If the allowCredentials option was given when this authentication ceremony was initiated,
  // verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
  if (!isAllowedCredentialId(credential.id)) {
    throw new Error('Credential ID is not allowed')
  }

  // Step 2: Identify the user being authenticated and verify that this user is the owner of the public key
  // credential source credentialSource identified by credential.id:

  // Step 3: Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
  // for your use case), look up the corresponding credential public key.
  if (!credential) {
    throw new Error('Could not find credential with that ID')
  }
  const publicKey = credential.publicKeyJwk
  if (!publicKey) {
    throw new Error('Could not read stored credential public key')
  }

  // Step 4: Let cData, authData and sig denote the value of credential’s response's clientDataJSON,
  // authenticatorData, and signature respectively.
  const cData = response.clientDataJSON
  const authData = Buffer.from(response.authenticatorData, 'base64')
  const sig = Buffer.from(response.signature, 'base64')

  // Step 5: Let JSONtext be the result of running UTF-8 decode on the value of cData.
  // => Expect it's already in UTF-8

  // Step 6: Let C, the client data claimed as used for the signature, be the result of running an
  // implementation-specific JSON parser on JSONtext.
  let C
  try {
    C = JSON.parse(cData)
  } catch (e) {
    throw new Error('Property "clientDataJSON" could not be parsed')
  }

  // Step 7: Verify that the value of C.type is the string webauthn.get.
  if (C.type !== 'webauthn.get') {
    throw new Error('The value of property "clientDataJson.type" is not "webauhn.get"')
  }

  // Step 8: Verify that the value of C.challenge matches the challenge that was sent to the
  // authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
  const _expectedChallenge = retrieveValue(expectedChallenge)
  if (C.challenge !== _expectedChallenge) {
    throw new Error(`Invalid value in "cliengDataJSON.challenge". Expected challenge "${_expectedChallenge}"`)
  }

  // Step 9: Verify that the value of C.origin matches the Relying Party's origin.
  const _expectedHostname = retrieveValue(expectedHostname)
  checkOrigin(C.origin, _expectedHostname)

  // Step 10: Verify that the value of C.tokenBinding.status matches the state of Token Binding for
  // the TLS connection over which the attestation was obtained. If Token Binding was used on that
  // TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token
  // Binding ID for the connection.
  if (C.tokenBinding) {
    if (showWarning) {
      console.warn('WARN: Verification of Token Binding is not implemented')
    }
  }

  const authenticatorData = parseAuthenticatorData(authData)

  // Step 11: Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the
  // Relying Party.
  const expectedRpIdHash = sha256(expectedHostname)
  if (!authenticatorData.rpIdHash.equals(expectedRpIdHash)) {
    throw new Error(`The value of "authData.rpIdHash" is wrong. Expected hash "${expectedRpIdHash}"`)
  }

  // Step 12: Verify that the User Present bit of the flags in authData is set.
  if ((authenticatorData.flags & 0b00000001) == 0) {
    throw new Error('User Present bit was not set in "authData.flags"')
  }

  // Step 13: If user verification is required for this assertion, verify that the User Verified bit
  // of the flags in authData is set.
  if ((authenticatorData.flags & 0b00000100) == 0) {
    throw new Error('User Verified bit was not set in "authData.flags"')
  }

  // Step 14: Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
  // extension outputs in the extensions in authData are as expected, considering the client extension input values
  // that were given as the extensions option in the get() call.
  if (authenticatorData.extensions) {
    // We didn't request any extensions. If extensionData is defined, fail.
    throw new Error('Received unexpected extension data')
  }

  // Step 15: Let hash be the result of computing a hash over the cData using SHA-256.
  const hash = sha256(cData)

  // Step 16: Using the credential public key looked up in step 3, verify that sig is a valid signature
  // over the binary concatenation of authData and hash.
  const verify = publicKey.kty === 'RSA' ? crypto.createVerify('RSA-SHA256') : crypto.createVerify('sha256')
  verify.update(authData)
  verify.update(hash)
  if (!verify.verify(jwkToPem(publicKey), sig)) {
    throw new Error('Could not verify signature')
  }

  // Step 17: If the signature counter value authData.signCount is nonzero or the value stored in
  // conjunction with credential’s id attribute is nonzero, then run the following sub-step:
  if (authenticatorData.signCount != 0 && authenticatorData.signCount < credential.signCount) {
    throw new Error(
      'Received signCount of ' + authenticatorData.signCount + '. Expected signCount > ' + credential.signCount
    )
  }

  // Update sign count
  if (updateSignCount) {
    if (updateSignCount instanceof Function) {
      updateSignCount({
        credentialId: credential.id,
        oldSignCount: credential.signCount,
        newSignCount: authenticatorData.signCount
      })
    } else {
      throw new Error('Parameter "updateSignCount" must be a function.')
    }
  }
}

module.exports = { registerNewCredential, verifyAssertion, registerAttestation }
