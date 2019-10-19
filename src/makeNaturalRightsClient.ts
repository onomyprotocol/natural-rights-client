import {
  NRClientCrypto,
  NRGrantKind,
  NRServiceInterface
} from '@natural-rights/common'
import { hashForSignature } from '@notabug/gun-sear'
import { addMemberToGroupAction } from './actions/addMemberToGroupAction'
import { authorizeClientAction } from './actions/authorizeClientAction'
import { createDocumentAction } from './actions/createDocumentAction'
import { createGroupAction } from './actions/createGroupAction'
import { deauthorizeClientAction } from './actions/deauthorizeClientAction'
import { decryptDocumentTextsAction } from './actions/decryptDocumentTextsAction'
import { encryptDocumentTextsAction } from './actions/encryptDocumentTextsAction'
import { grantAccessAction } from './actions/grantAccessAction'
import { loginAction } from './actions/loginAction'
import { registerAccountAction } from './actions/registerAccountAction'
import { removeGroupAdminAction } from './actions/removeGroupAdminAction'
import { removeMemberFromGroupAction } from './actions/removeMemberFromGroupAction'
import { revokeAccessAction } from './actions/revokeAccessAction'
import { signDocumentHashesAction } from './actions/signDocumentHashesAction'

// tslint:disable-next-line: typedef
export function makeNaturalRightsClient(
  service: NRServiceInterface,
  clientCrypto: NRClientCrypto
) {
  const {
    accountSignPubKey = '',
    clientCryptPubKey = '',
    clientSignPubKey = ''
  } = clientCrypto.publicKeys()

  /**
   * Ask the service if this client is authorized on an account
   *
   * @returns rootDocumentId and accountId if client is authorized on an account
   */
  async function login(): Promise<{
    rootDocumentId: string
    accountId: string
  }> {
    const result = await loginAction({
      clientCryptPubKey,
      clientCrypto,
      service
    })

    client.rootDocumentId = result.rootDocumentId
    client.accountId = result.accountId
    return result
  }

  /**
   * Create a new account in the service and login to it
   */
  async function registerAccount(): Promise<{
    rootDocumentId: string
    accountId: string
  }> {
    await registerAccountAction({
      clientCrypto,
      service
    })
    return login()
  }

  /**
   * Authorize another client on the currently logged in account
   *
   * @param clientToAuthSignPubKey The unique identifier of the client to authorize
   */
  async function authorizeClient(
    clientToAuthSignPubKey: string
  ): Promise<void> {
    await authorizeClientAction({
      accountSignPubKey: client.accountId,
      clientCrypto,
      clientToAuthSignPubKey,
      service
    })
  }

  /**
   * Deauthorize another client currently logged into this account
   *
   * @param clientToDeauthSignPubKey The unique identifier of the client to deauthorize
   */
  async function deauthorizeClient(
    clientToDeauthSignPubKey: string = ''
  ): Promise<void> {
    await deauthorizeClientAction({
      accountSignPubKey: client.accountId,
      clientCrypto,
      clientToDeauthSignPubKey: clientToDeauthSignPubKey || client.clientId,
      service
    })
  }

  /**
   * Create a new rights management group in the service
   *
   * @returns unique identifier for the created group
   */
  async function createGroup(): Promise<string> {
    return (await createGroupAction({
      accountSignPubKey: client.accountId,
      clientCrypto,
      service
    })).groupSignPubKey
  }

  /**
   * Add a member with read access to a natural rights group
   *
   * @param groupSignPubKey unique identifier of the group to add to
   * @param memberAccountSignPubKey unique identifier of the account to add
   */
  async function addReaderToGroup(
    groupSignPubKey: string,
    memberAccountSignPubKey: string
  ): Promise<void> {
    await addMemberToGroupAction({
      clientCrypto,
      groupSignPubKey,
      memberAccountSignPubKey,
      service
    })
  }

  /**
   * Add a member with sign access to a natural rights group
   *
   * @param groupSignPubKey unique identifier of the group to add to
   * @param memberAccountSignPubKey unique identifier of the account to add
   */
  async function addSignerToGroup(
    groupSignPubKey: string,
    memberAccountSignPubKey: string
  ): Promise<void> {
    await addMemberToGroupAction({
      canSign: true,
      clientCrypto,
      groupSignPubKey,
      memberAccountSignPubKey,
      service
    })
  }

  /**
   * Remove an existing member from a rights management group
   *
   * @param groupSignPubKey unique identifier of the group to add to
   * @param memberAccountSignPubKey unique identifier of the account to remove
   */
  async function removeMemberFromGroup(
    groupSignPubKey: string,
    memberAccountSignPubKey: string
  ): Promise<void> {
    await removeMemberFromGroupAction({
      clientCrypto,
      groupSignPubKey,
      memberAccountSignPubKey,
      service
    })
  }

  /**
   * Add an administrator to to a rights management group
   *
   * @param groupSignPubKey unique identifier of the group to add to
   * @param memberAccountSignPubKey unique identifier of the account to add
   */
  async function addAdminToGroup(
    groupSignPubKey: string,
    memberAccountSignPubKey: string
  ): Promise<void> {
    await addMemberToGroupAction({
      admin: true,
      clientCrypto,
      groupSignPubKey,
      memberAccountSignPubKey,
      service
    })
  }

  /**
   * Remove admin permissions from a member of a natural rights group
   *
   * Does not remove the admin from the group
   *
   * @param groupSignPubKey unique identifier of the group to remove from
   * @param adminToRemoveAccountSignPubKey unique identifier of the account to remove admin privileges from
   */
  async function removeAdminFromGroup(
    groupSignPubKey: string,
    adminToRemoveAccountSignPubKey: string
  ): Promise<void> {
    await removeGroupAdminAction({
      adminToRemoveAccountSignPubKey,
      clientCrypto,
      groupSignPubKey,
      service
    })
  }

  /**
   * Create and register a new document id/key in the natural rights service
   *
   * @returns the id and encryption key pair for the new document
   */
  async function createDocument(): Promise<{ id: string }> {
    const doc = await createDocumentAction({
      accountSignPubKey: client.accountId,
      clientCrypto,
      service
    })
    return {
      id: doc.documentSignPubKey
    }
  }

  /**
   * Grant read access on a document to a group or individual account
   *
   * @param documentSignPubKey unique identifier of the document to grant access to
   * @param grantKind what type of grant this is, a group or an individual account
   * @param granteeSignPubKey the unique identifier of the group or account to grant access to
   */
  async function grantReadAccess(
    documentSignPubKey: string,
    grantKind: NRGrantKind,
    granteeSignPubKey: string
  ): Promise<void> {
    if (!granteeSignPubKey) {
      throw new Error('missing granteeSignPubKey')
    }

    await grantAccessAction({
      clientCrypto,
      documentSignPubKey,
      grantKind,
      granteeSignPubKey,
      service
    })
  }

  /**
   * Grant sign access on a document to a group or individual account
   *
   * @param documentSignPubKey unique identifier of the document to grant access to
   * @param grantKind what type of grant this is, a group or an individual account
   * @param granteeSignPubKey the unique identifier of the group or account to grant access to
   */
  async function grantSignAccess(
    documentSignPubKey: string,
    grantKind: NRGrantKind,
    granteeSignPubKey: string
  ): Promise<void> {
    if (!granteeSignPubKey) {
      throw new Error('missing granteeSignPubKey')
    }

    await grantAccessAction({
      canSign: true,
      clientCrypto,
      documentSignPubKey,
      grantKind,
      granteeSignPubKey,
      service
    })
  }

  /**
   * Revoke access on a document from a group or individual account
   *
   * @param documentSignPubKey unique identifier of the document to grant access to
   * @param grantKind what type of grant this is, a group or an individual account
   * @param granteeSignPubKey the unique identifier of the group or account to grant access to
   */
  async function revokeAccess(
    documentSignPubKey: string,
    grantKind: NRGrantKind,
    granteeSignPubKey: string
  ): Promise<void> {
    await revokeAccessAction({
      clientCrypto,
      documentSignPubKey,
      grantKind,
      granteeSignPubKey,
      service
    })
  }

  /**
   * Sign an array of pre-hashed values on a document in natural rights
   *
   * @param documentSignPubKey unique identifier of the document to sign texts on
   * @param hashes array of hashes to sign
   * @returns a corresponding array of signatures
   */
  async function signDocumentHashes(
    documentSignPubKey: string,
    hashes: readonly string[]
  ): Promise<readonly string[]> {
    const res = await signDocumentHashesAction({
      clientCrypto,
      documentSignPubKey,
      hashes,
      service
    })
    return res.signatures
  }

  /**
   * Decrypt an array of texts from a document in natural rights
   *
   * @param documentSignPubKey unique identifier of the document to decrypt texts from
   * @param ciphertexts array of ciphertexts to decrypt
   * @returns a corresponding array of plaintexts
   */
  async function decryptDocumentTexts(
    documentSignPubKey: string,
    ciphertexts: readonly string[]
  ): Promise<readonly string[]> {
    const { plaintexts } = await decryptDocumentTextsAction({
      ciphertexts,
      clientCrypto,
      documentSignPubKey,
      service
    })

    return plaintexts
  }

  /**
   * Sign an array of texts on a document in natural rights
   *
   * @param documentSignPubKey unique identifier of the document to sign texts on
   * @param textsToSign array of strings to sign
   * @returns a corresponding array of signatures
   */
  async function signDocumentTexts(
    documentSignPubKey: string,
    textsToSign: readonly string[]
  ): Promise<readonly string[]> {
    const hashes = await Promise.all(
      textsToSign.map<Promise<string>>(hashForSignature)
    )
    const res = await signDocumentHashesAction({
      clientCrypto,
      documentSignPubKey,
      hashes,
      service
    })
    return res.signatures
  }

  /**
   * Encrypt an array of texts for a document in natural rights
   *
   * @param documentSignPubKey unique identifier of the document to encrypt texts for
   * @param plaintexts array of plaintexts to encrypt
   */
  async function encryptDocumentTexts(
    documentSignPubKey: string,
    plaintexts: readonly string[]
  ): Promise<
    ReadonlyArray<
      | string
      | {
          readonly ct: any
          readonly iv: any
          readonly s: any
        }
    >
  > {
    const { ciphertexts } = await encryptDocumentTextsAction({
      clientCrypto,
      documentSignPubKey,
      plaintexts,
      service
    })

    return ciphertexts
  }

  const client = {
    accountId: accountSignPubKey,
    addAdminToGroup,
    addReaderToGroup,
    addSignerToGroup,
    authorizeClient,
    clientId: clientSignPubKey,
    createDocument,
    createGroup,
    deauthorizeClient,
    decryptDocumentTexts,
    encryptDocumentTexts,
    grantReadAccess,
    grantSignAccess,
    login,
    registerAccount,
    removeAdminFromGroup,
    removeMemberFromGroup,
    revokeAccess,
    rootDocumentId: '',
    signDocumentHashes,
    signDocumentTexts
  }

  return client
}
