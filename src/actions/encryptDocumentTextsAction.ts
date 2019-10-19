import {
  NRClientCrypto,
  NRDecryptDocumentAction,
  NRDecryptDocumentResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function encryptDocumentTextsAction({
  clientCrypto,
  documentSignPubKey,
  plaintexts,
  service
}: {
  clientCrypto: NRClientCrypto
  documentSignPubKey: string
  plaintexts: readonly string[]
  service: NRServiceInterface
}): Promise<{
  readonly ciphertexts: readonly string[]
}> {
  if (!clientCrypto.encryptDocumentTexts) {
    throw new Error('clientCrypto does not support encryptDocumentTexts')
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

  const res = await clientCrypto.encryptDocumentTexts({
    documentEncCryptPrivKey: (result as NRDecryptDocumentResult).payload
      .encCryptPrivKey,
    plaintexts
  })

  return {
    ciphertexts: res.ciphertexts
  }
}
