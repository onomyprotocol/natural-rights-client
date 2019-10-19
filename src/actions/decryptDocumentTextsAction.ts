import {
  NRClientCrypto,
  NRDecryptDocumentAction,
  NRDecryptDocumentResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function decryptDocumentTextsAction({
  ciphertexts,
  clientCrypto,
  documentSignPubKey,
  service
}: {
  clientCrypto: NRClientCrypto
  documentSignPubKey: string
  ciphertexts: readonly string[]
  service: NRServiceInterface
}): Promise<{
  readonly plaintexts: readonly string[]
}> {
  if (!clientCrypto.decryptDocumentTexts) {
    throw new Error('clientCrypto does not support decryptDocumentTexts')
  }

  const actions: readonly [NRDecryptDocumentAction] = [
    {
      payload: {
        documentId: documentSignPubKey
      },
      type: 'DecryptDocument'
    }
  ]

  const response = await service.request(
    await clientCrypto.signRequest({ actions })
  )
  throwResponseErrors(response)
  const result = response.results.find(({ type }) => type === 'DecryptDocument')

  if (!result) {
    throw new Error('No DecryptDocument result')
  }

  const res = await clientCrypto.decryptDocumentTexts({
    ciphertexts,
    documentEncCryptPrivKey: (result as NRDecryptDocumentResult).payload
      .encCryptPrivKey
  })

  return {
    plaintexts: res.plaintexts
  }
}
