import {
  NRClientCrypto,
  NRCreateDocumentAction,
  NRCreateDocumentResult,
  NRGetKeyPairsAction,
  NRGetKeyPairsResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function createDocumentAction({
  accountSignPubKey,
  clientCrypto,
  service
}: {
  accountSignPubKey: string
  clientCrypto: NRClientCrypto
  service: NRServiceInterface
}): Promise<{
  readonly documentSignPubKey: string
  readonly documentCryptPubKey: string
  readonly documentEncCryptPrivKey: string
}> {
  if (!clientCrypto.createDocument) {
    throw new Error('clientCrypto does not support createDocument')
  }

  const actions: readonly [NRGetKeyPairsAction] = [
    {
      payload: {
        id: accountSignPubKey,
        kind: 'account'
      },
      type: 'GetKeyPairs'
    }
  ]

  const response = await service.request(
    await clientCrypto.signRequest({ actions })
  )

  throwResponseErrors(response)

  const keyPairsResult = response.results.find(
    ({ type }) => type === 'GetKeyPairs'
  )

  if (!keyPairsResult) {
    throw new Error('No GetKeyPairs result')
  }

  const keyPairs = (keyPairsResult as NRGetKeyPairsResult).payload

  const document = await clientCrypto.createDocument({
    accountCryptPubKey: keyPairs.cryptPubKey
  })

  const createDocActions: readonly [NRCreateDocumentAction] = [
    {
      payload: {
        creatorId: accountSignPubKey,
        cryptAccountId: accountSignPubKey,

        cryptPubKey: document.documentCryptPubKey,
        encCryptPrivKey: document.documentEncCryptPrivKey
      },
      type: 'CreateDocument'
    }
  ]

  const createResponse = await service.request(
    await clientCrypto.signRequest({ actions: createDocActions })
  )
  throwResponseErrors(createResponse)
  const result = createResponse.results.find(
    ({ type }) => type === 'CreateDocument'
  )

  if (!result) {
    throw new Error('No result')
  }

  return {
    ...document,
    documentSignPubKey: (result as NRCreateDocumentResult).payload.documentId
  }
}
