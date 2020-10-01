import dagCBOR from 'ipld-dag-cbor'
import CID from 'cids'
import multihashes from 'multihashes'
import * as u8a from 'uint8arrays'
import varint from 'varint'

const DAG_CBOR_CODE = 113
const ID_MULTIHASH = 0
const ENC_BLOCK_SIZE = 24

export interface EncodedPayload {
  cid: CID
  linkedBlock: Uint8Array
}

export async function encodePayload(payload: Record<string, any>): Promise<EncodedPayload> {
  const block = new Uint8Array(dagCBOR.util.serialize(payload))
  return {
    cid: await dagCBOR.util.cid(block),
    linkedBlock: block,
  }
}

function pad(b: Uint8Array, blockSize = ENC_BLOCK_SIZE): Uint8Array {
  // Pads with 0s.
  // Since the multihash defines it's length we don't need any special
  // method of figuring out which bytes are just padding.
  const padLen = (blockSize - (b.length % blockSize)) % blockSize
  // final modulus bs, since if b.length % bs == 24 we don't
  // want to add another 24 bytes.
  return u8a.concat([b, new Uint8Array(padLen)])
}

function unpadCIDBytes(b: Uint8Array): CID {
  // Find where multihash starts.
  // Multihash lenght is the 4th varint.
  let offset = 0
  let mhLen
  for (let i = 0; i < 4; i++) {
    mhLen = varint.decode(b, offset)
    offset += varint.decode.bytes
  }
  // Slice padding.
  return new CID(b.slice(0, offset + mhLen))
}

export function encodeIdentityCID(obj: Record<string, any>): CID {
  const block = dagCBOR.util.serialize(obj)
  const idMultiHash = multihashes.encode(block, ID_MULTIHASH)
  return new CID(1, DAG_CBOR_CODE, idMultiHash)
}

export function decodeIdentityCID(cid: CID): Record<string, any> {
  CID.validateCID(cid)
  if (cid.code !== DAG_CBOR_CODE) throw new Error('CID codec must be dag-cbor')
  const { code, digest } = multihashes.decode(cid.multihash)
  if (code !== ID_MULTIHASH) throw new Error('CID must use identity multihash')
  return dagCBOR.util.deserialize(digest)
}

export function prepareCleartext(cleartext: Record<string, any>, blockSize?: number): Uint8Array {
  return pad(encodeIdentityCID(cleartext).bytes, blockSize)
}

export function decodeCleartext(b: Uint8Array): Record<string, any> {
  return decodeIdentityCID(unpadCIDBytes(b))
}
