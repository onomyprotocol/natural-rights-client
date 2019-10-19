import {
  NRClientCrypto,
  NRRemoveAdminFromGroupAction,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function removeGroupAdminAction({
  clientCrypto,
  service,
  groupSignPubKey,
  adminToRemoveAccountSignPubKey
}: {
  adminToRemoveAccountSignPubKey: string
  clientCrypto: NRClientCrypto
  groupSignPubKey: string
  service: NRServiceInterface
}): Promise<void> {
  const actions: readonly [NRRemoveAdminFromGroupAction] = [
    {
      payload: {
        accountId: adminToRemoveAccountSignPubKey,
        groupId: groupSignPubKey
      },
      type: 'RemoveAdminFromGroup'
    }
  ]
  throwResponseErrors(
    await service.request(await clientCrypto.signRequest({ actions }))
  )
}
