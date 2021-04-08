declare module 'ipld-dag-cbor' {
  import type CID from 'cids'

  export type UserOptions = { cidVersion?: number; hashAlg?: number }

  export namespace util {
    function cid(binaryBlob: any, userOptions?: UserOptions): Promise<CID>
    function serialize(node: any): Uint8Array
    function deserialize(b: Uint8Array): Record<string, any>
  }
}

declare module 'varint' {
  export function decode(b: Uint8Array, offset: number): number
  export namespace decode {
    export let bytes: number
  }
}
