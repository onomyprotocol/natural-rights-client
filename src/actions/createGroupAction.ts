import {
  NRAddAdminToGroupAction,
  NRAddMemberToGroupAction,
  NRClientCrypto,
  NRCreateGroupAction,
  NRGetKeyPairsAction,
  NRGetKeyPairsResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function createGroupAction({
  accountSignPubKey,
  clientCrypto,
  service
}: {
  accountSignPubKey: string
  clientCrypto: NRClientCrypto
  service: NRServiceInterface
}): Promise<{
  readonly groupCryptPubKey: string
  readonly groupEncCryptPrivKey: string
  readonly groupEncSignPrivKey: string
  readonly groupSignPubKey: string
}> {
  if (!clientCrypto.createGroup) {
    throw new Error('ClientCrypto does not support createGroup')
  }

  if (!clientCrypto.createMembership) {
    throw new Error('ClientCrypto does not support createMembership')
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

  const group = await clientCrypto.createGroup({
    accountCryptPubKey: keyPairs.cryptPubKey
  })

  const createGroupActions: readonly [
    NRCreateGroupAction,
    NRAddMemberToGroupAction,
    NRAddAdminToGroupAction
  ] = [
    {
      payload: {
        accountId: accountSignPubKey,
        cryptPubKey: group.groupCryptPubKey,
        encCryptPrivKey: group.groupEncCryptPrivKey,
        encSignPrivKey: group.groupEncSignPrivKey,
        groupId: group.groupSignPubKey
      },
      type: 'CreateGroup'
    },
    {
      payload: {
        accountId: accountSignPubKey,
        canSign: true,
        cryptTransformKey: group.memberCryptTransformKey,
        groupId: group.groupSignPubKey
      },
      type: 'AddMemberToGroup'
    },
    {
      payload: {
        accountId: accountSignPubKey,
        encCryptPrivKey: group.groupEncCryptPrivKey!,
        groupId: group.groupSignPubKey
      },
      type: 'AddAdminToGroup'
    }
  ]

  throwResponseErrors(
    await service.request(
      await clientCrypto.signRequest({ actions: createGroupActions })
    )
  )

  return group
}
