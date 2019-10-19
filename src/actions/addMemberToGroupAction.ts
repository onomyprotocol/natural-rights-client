import {
  NRAction,
  NRAddAdminToGroupAction,
  NRAddMemberToGroupAction,
  NRClientCrypto,
  NRGetKeyPairsAction,
  NRGetKeyPairsResult,
  NRGetPubKeysAction,
  NRGetPubKeysResult,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function addMemberToGroupAction({
  admin = false,
  canSign = false,
  clientCrypto,
  groupSignPubKey,
  memberAccountSignPubKey,
  service
}: {
  admin?: boolean
  canSign?: boolean
  clientCrypto: NRClientCrypto
  groupSignPubKey: string
  memberAccountSignPubKey: string
  service: NRServiceInterface
}): Promise<{
  readonly memberCryptTransformKey: string
  readonly encCryptPrivKey?: string | undefined
}> {
  if (!clientCrypto.createMembership) {
    throw new Error('clientCrypto does not support createMembership')
  }

  const actions: readonly [NRGetPubKeysAction, NRGetKeyPairsAction] = [
    {
      payload: {
        id: memberAccountSignPubKey,
        kind: 'account'
      },
      type: 'GetPubKeys'
    },
    {
      payload: {
        id: groupSignPubKey,
        kind: 'group'
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

  const membership = await clientCrypto.createMembership({
    admin,
    groupCryptPubKey: keyPairs.cryptPubKey,
    groupEncCryptPrivKey: keyPairs.encCryptPrivKey,
    memberCryptPubKey: (pubKeysResult as NRGetPubKeysResult).payload.cryptPubKey
  })

  const addMemberAction: NRAddMemberToGroupAction = {
    payload: {
      accountId: memberAccountSignPubKey,
      canSign: admin || canSign,
      cryptTransformKey: membership.memberCryptTransformKey,
      groupId: groupSignPubKey
    },
    type: 'AddMemberToGroup'
  }

  // tslint:disable-next-line: readonly-array
  const addMemberActions: NRAction[] = [addMemberAction]

  if (admin && membership.encCryptPrivKey) {
    const addAdminAction: NRAddAdminToGroupAction = {
      payload: {
        accountId: memberAccountSignPubKey,
        encCryptPrivKey: membership.encCryptPrivKey,
        groupId: groupSignPubKey
      },
      type: 'AddAdminToGroup'
    }
    addMemberActions.push(addAdminAction)
  }

  throwResponseErrors(
    await service.request(
      await clientCrypto.signRequest({ actions: addMemberActions })
    )
  )
  return membership
}
