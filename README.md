# webauthn-js: A webauthn server lib for node.js

## Motivation
When I was looking for a server implementation of [webauthn](https://www.w3.org/TR/webauthn/) in JS, I stumpled over an [webauthn example app] (https://github.com/MicrosoftEdge/webauthnsample) made by the Microsoft Edge team. In contrast to other server implementations in JS it worked straight away with my FIDO2 authenticators. So I decided to extract the code and build a server lib.

## Installation
```sh
npm i @frenatix/webauthn-js
```

## Usage
```js
const webauthn = require('@frenatix/webauth-js')
```

## API

### `registerNewCredential`
```js
const authenticatorData = webauthn.registerNewCredential({
  response: { // from authenticator
    id: 'BBOD...',
    clientDataJSON: '{"type":"webauthn.create","challenge":"123","origin":"http://localhost",":false}',
    attestationObject: 'o2NmbXRmcG...'
  },
  expectedChallenge: '123,
  expectedHostname: 'localhost',
  isValidCredentialId: (credentialId) => { /*...*/ },
  saveUserCredential: ({id, publicKeyJwk, signCount}) => { /*...*/ },
})
```
#### Parameters

| Name | Type | Description |
| --- |--- | --- |
| `response` | Object | The response of the authenticator (described [here](https://www.w3.org/TR/webauthn/#authenticatorresponse)). It consists of the properties `clientDataJSON` and `attestationObject` |
| `expectedChallenge` | string \| function | The expected challenge string which was sent to the client's authenticator |
| `expectedHostname` | string \| function | The hostname for this credential |
| `isValidCredentialId` | function | Check if the credential is already used |
| `saveUserCredential` | function | Callback function when credential creation was successful |
