import * as Block from 'multiformats/block'
import { CID } from 'multiformats/cid'
import { sha256 } from 'multiformats/hashes/sha2'
import { identity } from 'multiformats/hashes/identity'
import { base64url } from 'multiformats/bases/base64'
import * as dagCBOR from '@ipld/dag-cbor'

const ENC_BLOCK_SIZE = 24

export interface EncodedPayload {
  cid: CID
  linkedBlock: Uint8Array
}

export async function encodePayload(payload: Record<string, any>): Promise<EncodedPayload> {
  const block = await Block.encode({ value: payload, codec: dagCBOR, hasher: sha256 })
  return {
    cid: block.cid,
    linkedBlock: block.bytes,
  }
}

export function toJWSPayload(payload: EncodedPayload | CID): string {
  let cid = CID.asCID(payload)
  if (!cid) {
    cid = CID.asCID((payload as EncodedPayload).cid)
  }
  if (!cid) {
    throw new Error('Payload must be an EncodedPayload or a CID')
  }
  return base64url.encode(cid.bytes).slice(1)
}

// map a DagJWS to an array of JWS strings that verifyJWS() will be able to verify
export function toJWSStrings(jose: Record<string, unknown>): Array<string> {
  if (
    typeof jose === 'object' &&
    typeof jose.payload === 'string' &&
    Array.isArray(jose.signatures)
  ) {
    return jose.signatures.map((signature: Record<string, unknown>) => {
      if (
        typeof signature !== 'object' ||
        typeof signature.protected !== 'string' ||
        typeof signature.signature !== 'string'
      ) {
        throw new Error('Object must be a DagJWS')
      }
      return `${signature.protected}.${jose.payload}.${signature.signature}` // eslint-disable-line
    }, [])
  }
  throw new Error('Object must be a DagJWS')
}

function pad(b: Uint8Array, blockSize = ENC_BLOCK_SIZE): Uint8Array {
  // Pads with 0s.
  // Since the multihash defines it's length we don't need any special
  // method of figuring out which bytes are just padding.
  const padLen = (blockSize - (b.length % blockSize)) % blockSize
  // final modulus bs, since if b.length % bs == 24 we don't
  // want to add another 24 bytes.
  const bytes = new Uint8Array(b.length + padLen)
  bytes.set(b, 0)
  return bytes
}

export async function encodeIdentityCID(obj: Record<string, any>): Promise<CID> {
  const block = await Block.encode({ value: obj, codec: dagCBOR, hasher: identity })
  return block.cid
}

export function decodeIdentityCID(cid: CID): Record<string, any> {
  cid = CID.asCID(cid)
  if (cid.code !== dagCBOR.code) throw new Error('CID codec must be dag-cbor')
  if (cid.multihash.code !== identity.code) throw new Error('CID must use identity multihash')
  return dagCBOR.decode(cid.multihash.digest)
}

export async function prepareCleartext(
  cleartext: Record<string, any>,
  blockSize?: number
): Promise<Uint8Array> {
  return pad((await encodeIdentityCID(cleartext)).bytes, blockSize)
}

export function decodeCleartext(b: Uint8Array): Record<string, any> {
  return decodeIdentityCID(CID.decodeFirst(b)[0])
}
