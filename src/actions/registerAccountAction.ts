import {
  NRAction,
  NRAuthorizeClientAction,
  NRClientCrypto,
  NRInitializeAccountAction,
  NRServiceInterface
} from '@natural-rights/common'
import { throwResponseErrors } from '../lib/throwResponseErrors'

export async function registerAccountAction({
  clientCrypto,
  service
}: {
  clientCrypto: NRClientCrypto
  service: NRServiceInterface
}): Promise<{
  rootDoc: {
    readonly documentCryptPubKey: string
    readonly documentEncCryptPrivKey: string
  }
  accountCryptPubKey: string
  accountSignPubKey: string
}> {
  if (!clientCrypto.createDocument) {
    throw new Error('clientCrypto does not support createDocument')
  }

  if (!clientCrypto.createAccount) {
    throw new Error('clientCrypto does not support createAccount')
  }

  if (!clientCrypto.createClientAuth) {
    throw new Error('clientCrypto does not support createClientAuth')
  }

  const pubKeys = clientCrypto.publicKeys()

  const { clientSignPubKey, clientCryptPubKey } = pubKeys
  let { accountCryptPubKey, accountSignPubKey } = pubKeys
  let accountEncCryptPrivKey = ''
  let accountEncSignPrivKey = ''
  let clientCryptTransformKey = ''

  if (
    clientCrypto.createAccount &&
    (!accountCryptPubKey || !accountSignPubKey)
  ) {
    const created = await clientCrypto.createAccount()
    accountCryptPubKey = created.accountCryptPubKey
    accountSignPubKey = created.accountSignPubKey

    if (created.accountEncCryptPrivKey) {
      accountEncCryptPrivKey = created.accountEncCryptPrivKey
    }
    if (created.accountEncSignPrivKey) {
      accountEncSignPrivKey = created.accountEncSignPrivKey
    }

    if (created.clientCryptTransformKey) {
      clientCryptTransformKey = created.clientCryptTransformKey
    }
  }

  if (!accountCryptPubKey || !accountSignPubKey) {
    throw new Error('Unable to create account')
  }

  const rootDoc = await clientCrypto.createDocument({
    accountCryptPubKey
  })

  const initAccount: NRInitializeAccountAction = {
    payload: {
      accountId: accountSignPubKey,

      cryptPubKey: accountCryptPubKey,
      encCryptPrivKey: accountEncCryptPrivKey,
      encSignPrivKey: accountEncSignPrivKey,

      rootDocCryptPubKey: rootDoc.documentCryptPubKey,
      rootDocEncCryptPrivKey: rootDoc.documentEncCryptPrivKey,

      signPubKey: accountSignPubKey
    },
    type: 'InitializeAccount'
  }

  // tslint:disable-next-line: readonly-array
  const actions: NRAction[] = [initAccount]

  if (clientSignPubKey && clientCryptPubKey && clientCryptTransformKey) {
    const authClient: NRAuthorizeClientAction = {
      payload: {
        accountId: accountSignPubKey,
        clientId: clientSignPubKey,
        cryptTransformKey: clientCryptTransformKey
      },
      type: `AuthorizeClient`
    }

    actions.push(authClient)
  }

  throwResponseErrors(
    await service.request(await clientCrypto.signRequest({ actions }))
  )

  return {
    accountCryptPubKey,
    accountSignPubKey,
    rootDoc
  }
}
