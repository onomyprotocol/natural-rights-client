import {
  NRClientCrypto,
  NRGrantKind,
  NRRevokeAccessAction,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function revokeAccessAction({
  clientCrypto,
  documentSignPubKey,
  grantKind,
  granteeSignPubKey,
  service
}: {
  clientCrypto: NRClientCrypto
  documentSignPubKey: string
  granteeSignPubKey: string
  grantKind: NRGrantKind
  service: NRServiceInterface
}): Promise<void> {
  const actions: readonly [NRRevokeAccessAction] = [
    {
      payload: {
        documentId: documentSignPubKey,
        id: granteeSignPubKey,
        kind: grantKind
      },
      type: 'RevokeAccess'
    }
  ]
  throwResponseErrors(
    await service.request(await clientCrypto.signRequest({ actions }))
  )
}
