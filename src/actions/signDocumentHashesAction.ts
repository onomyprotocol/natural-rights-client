import {
  NRClientCrypto,
  NRServiceInterface,
  NRSignDocumentAction,
  NRSignDocumentResult
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function signDocumentHashesAction({
  clientCrypto,
  documentSignPubKey,
  hashes,
  service
}: {
  clientCrypto: NRClientCrypto
  documentSignPubKey: string
  hashes: readonly string[]
  service: NRServiceInterface
}): Promise<{
  signatures: readonly string[]
}> {
  const actions: readonly [NRSignDocumentAction] = [
    {
      payload: {
        documentId: documentSignPubKey,
        hashes
      },
      type: 'SignDocument'
    }
  ]

  const response = await await service.request(
    await clientCrypto.signRequest({ actions })
  )
  throwResponseErrors(response)
  const result = response.results.find(({ type }) => type === 'SignDocument')

  if (!result) {
    throw new Error('No SignDocument result')
  }

  return {
    signatures: (result as NRSignDocumentResult).payload.signatures
  }
}
