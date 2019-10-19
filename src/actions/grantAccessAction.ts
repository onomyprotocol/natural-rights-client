import {
  NRClientCrypto,
  NRDecryptDocumentAction,
  NRDecryptDocumentResult,
  NRGetPubKeysAction,
  NRGetPubKeysResult,
  NRGrantAccessAction,
  NRGrantKind,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function grantAccessAction({
  canSign = false,
  clientCrypto,
  documentSignPubKey,
  granteeSignPubKey,
  grantKind,
  service
}: {
  canSign?: boolean
  clientCrypto: NRClientCrypto
  documentSignPubKey: string
  granteeSignPubKey: string
  grantKind: NRGrantKind
  service: NRServiceInterface
}): Promise<{
  readonly documentEncCryptPrivKeyForGrantee: string
}> {
  if (!clientCrypto.createGrant) {
    throw new Error('clientCrypto does not support createGrant')
  }

  const actions: readonly [NRGetPubKeysAction, NRDecryptDocumentAction] = [
    {
      payload: {
        id: granteeSignPubKey,
        kind: grantKind
      },
      type: 'GetPubKeys'
    },
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
  const decryptResult = response.results.find(
    ({ type }) => type === 'DecryptDocument'
  )
  const pubKeysResult = response.results.find(
    ({ type }) => type === 'GetPubKeys'
  )

  if (!pubKeysResult) {
    throw new Error('No GetPubKeys result')
  }

  if (!decryptResult) {
    throw new Error('No DecryptDocument result')
  }

  const grant = await clientCrypto.createGrant({
    documentEncCryptPrivKey: (decryptResult as NRDecryptDocumentResult).payload
      .encCryptPrivKey,
    granteeCryptPubKey: (pubKeysResult as NRGetPubKeysResult).payload
      .cryptPubKey
  })

  const grantActions: readonly [NRGrantAccessAction] = [
    {
      payload: {
        canSign,
        documentId: documentSignPubKey,
        encCryptPrivKey: grant.documentEncCryptPrivKeyForGrantee,
        id: granteeSignPubKey,
        kind: grantKind
      },
      type: 'GrantAccess'
    }
  ]

  await service.request(
    await clientCrypto.signRequest({ actions: grantActions })
  )

  return grant
}
