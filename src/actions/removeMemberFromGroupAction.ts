import {
  NRClientCrypto,
  NRRemoveMemberFromGroupAction,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function removeMemberFromGroupAction({
  clientCrypto,
  groupSignPubKey,
  memberAccountSignPubKey,
  service
}: {
  clientCrypto: NRClientCrypto
  groupSignPubKey: string
  memberAccountSignPubKey: string
  service: NRServiceInterface
}): Promise<void> {
  const actions: readonly [NRRemoveMemberFromGroupAction] = [
    {
      payload: {
        accountId: memberAccountSignPubKey,
        groupId: groupSignPubKey
      },
      type: 'RemoveMemberFromGroup'
    }
  ]
  throwResponseErrors(
    await service.request(await clientCrypto.signRequest({ actions }))
  )
}
