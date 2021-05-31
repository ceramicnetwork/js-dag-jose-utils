/* eslint-env jest */

import { CID } from 'multiformats/cid'
import {
  encodePayload,
  prepareCleartext,
  decodeCleartext,
  encodeIdentityCID,
  decodeIdentityCID,
  toJWSPayload,
  toJWSStrings
} from '../src/index'

describe('dag-jose-utils', () => {
  it('Properly encode payload', async () => {
    const payload1 = { abc: 123 }
    const enc1 = await encodePayload(payload1)
    expect(enc1).toMatchSnapshot()
    const payload2 = { aLink: enc1.cid }
    expect(await encodePayload(payload2)).toMatchSnapshot()
  })

  it('Encodes and decodes identity CIDs', async () => {
    const ct1 = { abc: 123 }
    const enc1 = await encodeIdentityCID(ct1)
    expect(enc1).toMatchSnapshot()
    expect(decodeIdentityCID(enc1)).toEqual(ct1)
    const ct2 = { aLink: enc1 }
    const enc2 = await encodeIdentityCID(ct2)
    expect(enc2).toMatchSnapshot()
    expect(decodeIdentityCID(enc2).aLink.bytes).toEqual(ct2.aLink.bytes)
  })

  it('Prepare and decode cleartext', async () => {
    const ct1 = { abc: 123 }
    const enc1 = await prepareCleartext(ct1)
    expect(enc1).toMatchSnapshot()
    expect(decodeCleartext(enc1)).toEqual(ct1)
    const ct2 = { aLink: enc1 }
    const enc2 = await prepareCleartext(ct2)
    expect(enc2).toMatchSnapshot()
    expect(decodeCleartext(enc2).aLink.bytes).toEqual(ct2.aLink.bytes)
  })

  it('Creates a JWS payload from a CID', () => {
    const msg = 'Payload must be an EncodedPayload or a CID'
    let notCID = 'foireufhiuh'
    expect(() => toJWSPayload(notCID)).toThrowError(msg)
    // @ts-ignore
    notCID = { my: 'payload' }
    expect(() => toJWSPayload(notCID)).toThrowError(msg)
    const cid = CID.parse('bafyreiejkvsvdq4smz44yuwhfymcuvqzavveoj2at3utujwqlllspsqr6q')
    expect(toJWSPayload(cid))
      .toBe('AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0')
    expect(toJWSPayload({ cid, linkedBlock: new Uint8Array([1, 2]) }))
      .toBe('AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0')
  })

  it('Creates JWS string namedtuples from DagJWS objects', () => {
    const msg = 'Object must be a DagJWS'
    expect(() => toJWSStrings('nope')).toThrowError(msg)
    expect(() => toJWSStrings({ payload: 'nope' })).toThrowError(msg)
    expect(() => toJWSStrings({ payload: 'nope', signatures: 'nope' })).toThrowError(msg)
    expect(() => toJWSStrings({ payload: 'nope', signatures: ['nope'] })).toThrowError(msg)
    expect(() => toJWSStrings({ payload: 'nope', signatures: [{ nope: 'nope' }] })).toThrowError(msg)
    expect(toJWSStrings({
      payload: 'AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0',
      signatures: [{
        signature: 'lxSptfM-Q9Y12o8IAjrTomyGZREeIYcIEaM9OO0IVOvhJOggkNyMnQOJnMnl5xMHmejLTSaTL2bnrqszDfBHVA',
        protected: 'eyJhbGciOiJFUzI1NksifQ'
      }, {
        signature: 'kxSptfM-Q9Y12o8IAjrTomyGZREeIYcIEaM9OO0IVOvhJOggkNyMnQOJnMnl5xMHmejLTSaTL2bnrqszDfBHVB',
        protected: 'dyJhbGciOiJFUzI1NksifR'
      }]
    })).toStrictEqual([
      'eyJhbGciOiJFUzI1NksifQ.AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0.lxSptfM-Q9Y12o8IAjrTomyGZREeIYcIEaM9OO0IVOvhJOggkNyMnQOJnMnl5xMHmejLTSaTL2bnrqszDfBHVA',
      'dyJhbGciOiJFUzI1NksifR.AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0.kxSptfM-Q9Y12o8IAjrTomyGZREeIYcIEaM9OO0IVOvhJOggkNyMnQOJnMnl5xMHmejLTSaTL2bnrqszDfBHVB'
    ])
  })
})
