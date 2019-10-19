import {
  NRClientCrypto,
  NRDeauthorizeClientAction,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function deauthorizeClientAction({
  accountSignPubKey,
  clientCrypto,
  clientToDeauthSignPubKey,
  service
}: {
  accountSignPubKey: string
  clientCrypto: NRClientCrypto
  clientToDeauthSignPubKey: string
  service: NRServiceInterface
}): Promise<void> {
  const actions: readonly [NRDeauthorizeClientAction] = [
    {
      payload: {
        accountId: accountSignPubKey,
        clientId: clientToDeauthSignPubKey
      },
      type: 'DeauthorizeClient'
    }
  ]

  throwResponseErrors(
    await service.request(await clientCrypto.signRequest({ actions }))
  )
}
