# webauthn-js: A webauthn server lib for node.js

## Motivation
When I was looking for a server implementation of [webauthn](https://www.w3.org/TR/webauthn/) in JS, I stumpled over an [webauthn example app](https://github.com/MicrosoftEdge/webauthnsample) made by the Microsoft Edge team. In contrast to other server implementations in JS it worked straight away with my FIDO2 authenticators. So I decided to extract the code and build a server lib.

## Installation
```sh
npm i @frenatix/webauthn-js
```

## Usage
```js
const webauthn = require('@frenatix/webauth-js')
```

## API

### `registerNewCredential()`
```js
const authenticatorData = webauthn.registerNewCredential({
  response: {
    // from authenticator
    id: 'BBOD...',
    clientDataJSON: '{"type":"webauthn.create","challenge":"123","origin":"http://localhost:3001",":false}',
    attestationObject: 'o2NmbXRmcG...'
  },
  expectedChallenge: '123',
  expectedHostname: 'localhost',
  isValidCredentialId: (credentialId) => {
    /*...*/
  },
  saveUserCredential: ({ id, publicKeyJwk, signCount }) => {
    /*...*/
  }
})
```

#### Parameters

| Name                  | Type                     | Description       |
| --------------------- | ------------------------ | ----------------- |
| `response`            | Object                   | The response of the authenticator (described [here](https://www.w3.org/TR/webauthn/#authenticatorresponse)). It consists of the properties `clientDataJSON` and `attestationObject` |
| `isValidChallenge`    | function({challenge})    | Should returns `true` if challenge check was successful |
| `expectedHostname`    | string \| function       | The hostname for this credential |
| `isValidCredentialId` | function({credentialId}) | Check if the credential is already used |
| `saveUserCredential`  | function                 | Callback function when credential creation was created |

### `verifyAssertion()`
```js
verifyAssertion({
  assertion: { 
    // from authenticator
    id: 'WICPLj...',
    clientDataJSON: '{"type":"webauthn.get","challenge":"123","origin":"http://localhost:3001","crossOrigin":false}',
    signature: 'MEUCIQD...',
    authenticatorData: 'SZYN5...',
  },
  credential: {
    // from storage
    id: 'AB123..',
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'MSNo3...',
      y: 'm9sY...'
    },
    signCount: 2
  }
})
```

## Demo Project
You can find a demo project how to use this lib [here](https://github.com/frenatix/webauthn-js-demo).
