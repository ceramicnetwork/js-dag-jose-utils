# dag-jose-utils


This library provides utilities for using the dag-jose ipld codec. It uses dag-cbor to encode payloads and cleartexts to CIDs.


## Installation
First install the package
```
$ npm i --save dag-jose-utils
```

## Importing
```ts
import {
  encodePayload,
  prepareCleartext,
  decodeCleartext,
  encodeIdentityCID,
  decodeIdentityCID
} from 'dag-jose-utils'
```

## API

### EncodedPayload
```ts
interface EncodedPayload {
  cid: CID
  linkedBlock: Uint8Array
}
```

### encodePayload(payload: Record<string, any>): Promise<EncodedPayload>
Prepares a payload to be signed in a JWS. Note that you will need to encode the `encodePayload.cid.bytes` as `base64url` before signing.

### prepareCleartext(cleartext: Record<string, any>, blockSize?: number): Uint8Array
Prepares a cleartext object to be encrypted in a JWE. By default the blockSize for padding is 24.

### decodeCleartext(b: Uint8Array): Record<string, any>
Decode a decrypted cleartext to an ipld object.

### encodeIdentityCID(obj: Record<string, any>): CID
Encode an ipld object as a CID that uses the identity hash.

### decodeIdentityCID(cid: CID): Record<string, any>
Decode an ipld object from a CID that uses the identity hash.


## Maintainer
[Joel Thorstensson](https://github.com/oed)


## License
MIT or APACHE
