import {
  NRClientCrypto,
  NRLoginAction,
  NRLoginActionResultPayload,
  NRLoginResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function loginAction({
  clientCrypto,
  clientCryptPubKey,
  service
}: {
  clientCryptPubKey: string
  clientCrypto: NRClientCrypto
  service: NRServiceInterface
}): Promise<NRLoginActionResultPayload> {
  const actions: readonly [NRLoginAction] = [
    {
      payload: {
        cryptPubKey: clientCryptPubKey
      },
      type: 'Login'
    }
  ]

  const response = await service.request(
    await clientCrypto.signRequest({ actions })
  )
  throwResponseErrors(response)
  const result = response.results.find(({ type }) => type === 'Login')

  if (!result) {
    throw new Error('No Login result')
  }

  return (result as NRLoginResult).payload
}
