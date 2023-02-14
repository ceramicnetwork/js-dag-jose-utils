import * as Block from 'multiformats/block';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { identity } from 'multiformats/hashes/identity';
import { base64url } from 'multiformats/bases/base64';
import * as dagCBOR from '@ipld/dag-cbor';
const ENC_BLOCK_SIZE = 24;
export async function encodePayload(payload) {
    const block = await Block.encode({
        value: payload,
        codec: dagCBOR,
        hasher: sha256
    });
    return {
        cid: block.cid,
        linkedBlock: block.bytes
    };
}
export function toJWSPayload(payload) {
    let cid = CID.asCID(payload);
    if (!cid) {
        cid = CID.asCID(payload.cid);
    }
    if (!cid) {
        throw new Error('Payload must be an EncodedPayload or a CID');
    }
    return base64url.encode(cid.bytes).slice(1);
}
// map a DagJWS to an array of JWS strings that verifyJWS() will be able to verify
export function toJWSStrings(jose) {
    if (typeof jose === 'object' && typeof jose.payload === 'string' && Array.isArray(jose.signatures)) {
        return jose.signatures.map((signature)=>{
            if (typeof signature !== 'object' || typeof signature.protected !== 'string' || typeof signature.signature !== 'string') {
                throw new Error('Object must be a DagJWS');
            }
            return `${signature.protected}.${jose.payload}.${signature.signature}` // eslint-disable-line
            ;
        }, []);
    }
    throw new Error('Object must be a DagJWS');
}
function pad(b, blockSize = ENC_BLOCK_SIZE) {
    // Pads with 0s.
    // Since the multihash defines it's length we don't need any special
    // method of figuring out which bytes are just padding.
    const padLen = (blockSize - b.length % blockSize) % blockSize;
    // final modulus bs, since if b.length % bs == 24 we don't
    // want to add another 24 bytes.
    const bytes = new Uint8Array(b.length + padLen);
    bytes.set(b, 0);
    return bytes;
}
export async function encodeIdentityCID(obj) {
    const block = await Block.encode({
        value: obj,
        codec: dagCBOR,
        hasher: identity
    });
    return block.cid;
}
export function decodeIdentityCID(cid) {
    const validcid = CID.asCID(cid);
    if (!validcid) throw new Error('CID could not be parsed');
    if (validcid.code !== dagCBOR.code) throw new Error('CID codec must be dag-cbor');
    if (validcid.multihash.code !== identity.code) throw new Error('CID must use identity multihash');
    return dagCBOR.decode(validcid.multihash.digest);
}
export async function prepareCleartext(cleartext, blockSize) {
    return pad((await encodeIdentityCID(cleartext)).bytes, blockSize);
}
export function decodeCleartext(b) {
    return decodeIdentityCID(CID.decodeFirst(b)[0]);
}
