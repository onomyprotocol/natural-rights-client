import {
  NRAuthorizeClientAction,
  NRClientCrypto,
  NRGetKeyPairsAction,
  NRGetKeyPairsResult,
  NRGetPubKeysAction,
  NRGetPubKeysResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function authorizeClientAction({
  accountSignPubKey,
  clientCrypto,
  clientToAuthSignPubKey,
  service
}: {
  accountSignPubKey: string
  clientCrypto: NRClientCrypto
  clientToAuthSignPubKey: string
  service: NRServiceInterface
}): Promise<void> {
  if (!clientCrypto.createClientAuth) {
    throw new Error('clientCrypto does not support createClientAuth')
  }

  const actions: readonly [NRGetPubKeysAction, NRGetKeyPairsAction] = [
    {
      payload: {
        id: clientToAuthSignPubKey,
        kind: 'client'
      },
      type: 'GetPubKeys'
    },
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

  const pubKeysResult = response.results.find(
    ({ type }) => type === 'GetPubKeys'
  )
  const keyPairsResult = response.results.find(
    ({ type }) => type === 'GetKeyPairs'
  )

  if (!pubKeysResult) {
    throw new Error('No GetPubKeys result')
  }

  if (!keyPairsResult) {
    throw new Error('No GetKeyPairs result')
  }

  const keyPairs = (keyPairsResult as NRGetKeyPairsResult).payload
  const clientPubKeys = (pubKeysResult as NRGetPubKeysResult).payload

  const {
    clientCryptTransformKey: cryptTransformKey
  } = await clientCrypto.createClientAuth({
    accountCryptPubKey: keyPairs.cryptPubKey,
    accountEncCryptPrivKey: keyPairs.encCryptPrivKey,
    clientCryptPubKey: clientPubKeys.cryptPubKey
  })

  const authorizeActions: readonly [NRAuthorizeClientAction] = [
    {
      payload: {
        accountId: accountSignPubKey,
        clientId: clientToAuthSignPubKey,
        cryptTransformKey
      },
      type: 'AuthorizeClient'
    }
  ]

  throwResponseErrors(
    await service.request(
      await clientCrypto.signRequest({ actions: authorizeActions })
    )
  )
}
