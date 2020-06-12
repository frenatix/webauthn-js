# webauthn-js: A webauthn server lib for node.js
<a href="https://www.npmjs.com/package/@frenatix/webauthn-js"><img src="https://img.shields.io/npm/v/@frenatix/webauthn-js.svg" alt="Version"></a>
<a href="https://github.com/frenatix/webauthn-js/blob/master/LICENSE"><img src="https://img.shields.io/github/license/frenatix/webauthn-js.svg" alt="License"></a>


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
const authenticatorData = await webauthn.registerNewCredential({
  response: {
    // from authenticator
    id: 'BBOD...',
    clientDataJSON: '{"type":"webauthn.create","challenge":"123","origin":"http://localhost:3001",":false}',
    attestationObject: 'o2NmbXRmcG...'
  },
  getValidChallengeToken: async (challenge) => {
    const challengeToken = //...
    return challengeToken
  },
  expectedHostname: 'localhost',
  isValidCredentialId: async (credentialId) => {
    /*...*/
  },
  saveUserCredential: async ({ id, publicKeyJwk, signCount, challengeToken }) => {
    /*...*/
  }
})
```

#### Parameters
| Name                     | Type                     | Description       |
| ------------------------ | ------------------------ | ----------------- |
| `response`               | Object                   | The response of the authenticator (described [here](https://www.w3.org/TR/webauthn/#authenticatorresponse)). It consists of the properties `clientDataJSON` and `attestationObject` |
| `getValidChallengeToken` | function(challenge)      | Should returns `true` if challenge check was successful |
| `expectedHostname`       | string \| function       | The hostname for this credential |
| `isValidCredentialId`    | function(credentialId)   | Check if the credential is already used |
| `saveUserCredential`     | function({id, publicKeyJwk, signCount, challengeToken}) | Callback function when credential creation was created |

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
  },
  getValidChallengeToken: async (challenge) => {
    const challengeToken = //...
    return challengeToken
  },
  expectedHostname: 'localhost',
  isAllowedCredentialId: (credentialId) => true,
  updateSignCount: async ({ credentialId, oldSignCount, newSignCount }) => {
    /*...*/
  }
})
```

#### Parameters
| Name                     | Type                     | Description       |
| ------------------------ | ------------------------ | ----------------- |
| `assertion`              | Object                   | The response of the authenticator (described [here](https://www.w3.org/TR/webauthn/#authenticatorassertionresponse)) |
| `getValidChallengeToken` | function(challenge)      | Should returns `true` if challenge check was successful |
| `expectedHostname`       | string \| function       | The hostname for this credential |
| `isAllowedCredentialId`  | function(credentialId)   | Check if the credential is already allowed |
| `updateSignCount`        | function({credentialId, oldSignCount, newSignCount}) | Callback function to update the sign count |

## Demo Project
You can find a demo project how to use this lib [here](https://github.com/frenatix/webauthn-js-demo).
