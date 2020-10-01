import * as u8a from 'uint8arrays'
import CID from 'cids'
import {
  encodePayload,
  prepareCleartext,
  decodeCleartext,
  encodeIdentityCID,
  decodeIdentityCID
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
    const enc1 = encodeIdentityCID(ct1)
    expect(enc1).toMatchSnapshot()
    expect(decodeIdentityCID(enc1)).toEqual(ct1)
    const ct2 = { aLink: enc1 }
    const enc2 = encodeIdentityCID(ct2)
    expect(enc2).toMatchSnapshot()
    expect(decodeIdentityCID(enc2).aLink.bytes).toEqual(ct2.aLink.bytes)
  })

  it('Prepare and decode cleartext', async () => {
    const ct1 = { abc: 123 }
    const enc1 = prepareCleartext(ct1)
    expect(enc1).toMatchSnapshot()
    expect(decodeCleartext(enc1)).toEqual(ct1)
    const ct2 = { aLink: enc1 }
    const enc2 = prepareCleartext(ct2)
    expect(enc2).toMatchSnapshot()
    expect(decodeCleartext(enc2).aLink.bytes).toEqual(ct2.aLink.bytes)
  })
})
