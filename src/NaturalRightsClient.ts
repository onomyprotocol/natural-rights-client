import {
  NRAction,
  NRAddAdminToGroupAction,
  NRAddMemberToGroupAction,
  NRAuthorizeClientAction,
  NRCreateDocumentAction,
  NRCreateDocumentResult,
  NRCreateGroupAction,
  NRDeauthorizeClientAction,
  NRDecryptDocumentAction,
  NRDecryptDocumentResult,
  NRGetKeyPairsAction,
  NRGetKeyPairsResultPayload,
  NRGetPubKeysAction,
  NRGetPubKeysResult,
  NRGetPubKeysResultPayload,
  NRGrantAccessAction,
  NRGrantKind,
  NRInitializeAccountAction,
  NRKeyPair,
  NRLoginActionResultPayload,
  NRRemoveAdminFromGroupAction,
  NRRemoveMemberFromGroupAction,
  NRRequest,
  NRResponse,
  NRResult,
  NRRevokeAccessAction,
  NRServiceInterface,
  NRSignatureKind,
  NRSignDocumentAction,
  NRSignDocumentResult,
  NRUpdateDocumentAction
} from '@natural-rights/common'

import {
  decrypt,
  encrypt,
  hashForSignature,
  pair as createPairs
} from '@notabug/gun-sear'

/**
 * Natural Rights Client
 *
 * Interacts with Natural Rights service to:
 * encrypt, decrypt, sign and manage access to documents
 */
export class NaturalRightsClient {
  public service: NRServiceInterface

  public accountId: string
  public rootDocumentId: string
  public clientId: string
  public clientCryptKeyPair: NRKeyPair
  public clientSignKeyPair: NRKeyPair

  constructor(
    service: NRServiceInterface,
    clientCryptKeyPair: NRKeyPair,
    clientSignKeyPair: NRKeyPair
  ) {
    this.service = service
    this.accountId = ''
    this.rootDocumentId = ''
    this.clientCryptKeyPair = clientCryptKeyPair
    this.clientSignKeyPair = clientSignKeyPair
    this.clientId = clientSignKeyPair.pubKey
  }

  /**
   * Ask the service if this client is authorized on an account
   *
   * @returns rootDocumentId and accountId if client is authorized on an account
   */
  public async login(): Promise<{
    rootDocumentId: string
    accountId: string
  }> {
    const response = await this._requestActions([
      {
        payload: {
          cryptPubKey: this.clientCryptKeyPair.pubKey
        },
        type: 'Login'
      }
    ])
    const result = response.results.find(({ type }) => type === 'Login')

    if (!result) {
      throw new Error('No Login result')
    }

    const {
      rootDocumentId,
      accountId
    } = result.payload as NRLoginActionResultPayload

    if (accountId) {
      this.accountId = accountId
      this.rootDocumentId = rootDocumentId
    }

    return { rootDocumentId, accountId }
  }

  /**
   * Create a new account in the service and login to it
   */
  public async registerAccount(): Promise<void> {
    if (this.accountId) {
      return
    }
    const accountSignKeyPair = await this.service.primitives.signKeyGen()
    const accountCryptKeyPair = await this.service.primitives.cryptKeyGen()
    const cryptTransformKey = await this.service.primitives.cryptTransformKeyGen(
      accountCryptKeyPair,
      this.clientCryptKeyPair.pubKey,
      this.clientSignKeyPair
    )
    const accountEncSignPrivKey = await this.service.primitives.encrypt(
      accountCryptKeyPair.pubKey,
      accountSignKeyPair.privKey,
      this.clientSignKeyPair
    )
    const accountEncCryptPrivKey = await this.service.primitives.encrypt(
      accountCryptKeyPair.pubKey,
      accountCryptKeyPair.privKey,
      this.clientSignKeyPair
    )

    // Private root
    const rootDocCryptKeyPair = await this.service.primitives.cryptKeyGen()

    const rootDocEncCryptPrivKey = await this.service.primitives.encrypt(
      accountCryptKeyPair.pubKey,
      rootDocCryptKeyPair.privKey,
      this.clientSignKeyPair
    )

    const actions: readonly [
      NRInitializeAccountAction,
      NRAuthorizeClientAction
    ] = [
      {
        payload: {
          cryptPubKey: accountCryptKeyPair.pubKey,
          encCryptPrivKey: accountEncCryptPrivKey,
          encSignPrivKey: accountEncSignPrivKey,

          rootDocCryptPubKey: rootDocCryptKeyPair.pubKey,
          rootDocEncCryptPrivKey,

          signPubKey: accountSignKeyPair.pubKey,

          accountId: accountSignKeyPair.pubKey
        },
        type: 'InitializeAccount'
      },
      {
        payload: {
          accountId: accountSignKeyPair.pubKey,
          clientId: this.clientId,
          cryptTransformKey
        },
        type: `AuthorizeClient`
      }
    ]

    try {
      await this._requestActions(actions)
    } catch (e) {
      throw e
    } finally {
      await this.login()
    }
  }

  /**
   * Authorize another client on the currently logged in account
   *
   * @param clientId The unique identifier of the client to authorize
   */
  public async authorizeClient(clientId: string): Promise<void> {
    const accountCryptKeyPair = await this._getEncryptionKeyPair(
      'account',
      this.accountId
    )
    const { cryptPubKey: clientCryptPubKey } = await this._getPublicKeys(
      'client',
      clientId
    )
    const cryptTransformKey = await this.service.primitives.cryptTransformKeyGen(
      accountCryptKeyPair,
      clientCryptPubKey,
      this.clientSignKeyPair
    )

    const actions: readonly [NRAuthorizeClientAction] = [
      {
        payload: {
          accountId: this.accountId,
          clientId,
          cryptTransformKey
        },
        type: 'AuthorizeClient'
      }
    ]

    await this._requestActions(actions)
  }

  /**
   * Deauthorize another client currently logged into this account
   *
   * @param clientId The unique identifier of the client to deauthorize
   */
  public async deauthorizeClient(clientId = ''): Promise<void> {
    const actions: readonly [NRDeauthorizeClientAction] = [
      {
        payload: {
          accountId: this.accountId,
          clientId: clientId || this.clientId
        },
        type: 'DeauthorizeClient'
      }
    ]
    await this._requestActions(actions)
    if (clientId === this.clientId || !clientId) {
      this.accountId = this.rootDocumentId = ''
    }
  }

  /**
   * Create a new rights management group in the service
   *
   * @returns unique identifier for the created group
   */
  public async createGroup(): Promise<string> {
    const ownerPubKey = await this._getEncryptionPublicKey(
      'account',
      this.accountId
    )
    const groupCryptKeyPair = await this.service.primitives.cryptKeyGen()
    const groupSignKeyPair = await this.service.primitives.signKeyGen()
    const encCryptPrivKey = await this.service.primitives.encrypt(
      ownerPubKey,
      groupCryptKeyPair.privKey,
      this.clientSignKeyPair
    )
    const encSignPrivKey = await this.service.primitives.encrypt(
      ownerPubKey,
      groupSignKeyPair.privKey,
      this.clientSignKeyPair
    )
    const cryptTransformKey = await this.service.primitives.cryptTransformKeyGen(
      groupCryptKeyPair,
      ownerPubKey,
      this.clientSignKeyPair
    )
    const groupId = groupSignKeyPair.pubKey

    const actions: readonly [
      NRCreateGroupAction,
      NRAddMemberToGroupAction,
      NRAddAdminToGroupAction
    ] = [
      {
        payload: {
          accountId: this.accountId,
          cryptPubKey: groupCryptKeyPair.pubKey,
          encCryptPrivKey,
          encSignPrivKey,
          groupId
        },
        type: 'CreateGroup'
      },
      {
        payload: {
          accountId: this.accountId,
          canSign: true,
          cryptTransformKey,
          groupId
        },
        type: 'AddMemberToGroup'
      },
      {
        payload: {
          accountId: this.accountId,
          encCryptPrivKey,
          groupId
        },
        type: 'AddAdminToGroup'
      }
    ]

    await this._requestActions(actions)
    return groupId
  }

  /**
   * Add a member with read access to a natural rights group
   *
   * @param groupId unique identifier of the group to add to
   * @param accountId unique identifier of the account to add
   */
  public async addReaderToGroup(
    groupId: string,
    accountId: string
  ): Promise<void> {
    const memberPubKey = await this._getEncryptionPublicKey(
      'account',
      accountId
    )
    const groupCryptKeyPair = await this._getEncryptionKeyPair('group', groupId)
    const cryptTransformKey = await this.service.primitives.cryptTransformKeyGen(
      groupCryptKeyPair,
      memberPubKey,
      this.clientSignKeyPair
    )

    const actions: readonly [NRAddMemberToGroupAction] = [
      {
        payload: {
          accountId,
          cryptTransformKey,
          groupId
        },
        type: 'AddMemberToGroup'
      }
    ]
    await this._requestActions(actions)
  }

  /**
   * Add a memver with sign access to a natural rights group
   *
   * @param groupId unique identifier of the group to add to
   * @param accountId unique identifier of the account to add
   */
  public async addSignerToGroup(
    groupId: string,
    accountId: string
  ): Promise<void> {
    const actions: readonly [NRAddMemberToGroupAction] = [
      {
        payload: {
          accountId,
          canSign: true,
          groupId
        },
        type: 'AddMemberToGroup'
      }
    ]
    await this._requestActions(actions)
  }

  /**
   * Remove an existing member from a rights management group
   *
   * @param groupId unique identifier of the group to add to
   * @param accountId unique identifier of the account to remove
   */
  public async removeMemberFromGroup(
    groupId: string,
    accountId: string
  ): Promise<void> {
    const actions: readonly [NRRemoveMemberFromGroupAction] = [
      {
        payload: {
          accountId,
          groupId
        },
        type: 'RemoveMemberFromGroup'
      }
    ]
    await this._requestActions(actions)
  }

  /**
   * Add an administrator to to a rights management group
   *
   * @param groupId unique identifier of the group to add to
   * @param accountId unique identifier of the account to add
   */
  public async addAdminToGroup(
    groupId: string,
    accountId: string
  ): Promise<void> {
    const memberPubKey = await this._getEncryptionPublicKey(
      'account',
      accountId
    )
    const groupCryptKeyPair = await this._getEncryptionKeyPair('group', groupId)
    const cryptTransformKey = await this.service.primitives.cryptTransformKeyGen(
      groupCryptKeyPair,
      memberPubKey,
      this.clientSignKeyPair
    )
    const encCryptPrivKey = await this.service.primitives.encrypt(
      memberPubKey,
      groupCryptKeyPair.privKey,
      this.clientSignKeyPair
    )

    const actions: readonly [
      NRAddMemberToGroupAction,
      NRAddAdminToGroupAction
    ] = [
      {
        payload: {
          accountId,
          canSign: true,
          cryptTransformKey,
          groupId
        },
        type: 'AddMemberToGroup'
      },
      {
        payload: {
          accountId,
          encCryptPrivKey,
          groupId
        },
        type: 'AddAdminToGroup'
      }
    ]

    await this._requestActions(actions)
  }

  /**
   * Remove admin permissions from a member of a natural rights group
   *
   * Does not remove the admin from the group
   *
   * @param groupId unique identifier of the group to remove from
   * @param accountId unique identifier of the account to remove admin privileges from
   */
  public async removeAdminFromGroup(
    groupId: string,
    accountId: string
  ): Promise<void> {
    const actions: readonly [NRRemoveAdminFromGroupAction] = [
      {
        payload: {
          accountId,
          groupId
        },
        type: 'RemoveAdminFromGroup'
      }
    ]
    await this._requestActions(actions)
  }

  /**
   * Create and register a new document id/key in the natural rights service
   *
   * @returns the id and encryption key pair for the new document
   */
  public async createDocument(): Promise<{
    id: string
    cryptKeyPair: NRKeyPair
  }> {
    const accountCryptPubKey = await this._getEncryptionPublicKey(
      'account',
      this.accountId
    )
    const pairs = await createPairs()

    const docCryptKeyPair = {
      privKey: pairs.epriv,
      pubKey: pairs.epub
    }

    const encCryptPrivKey = await this.service.primitives.encrypt(
      accountCryptPubKey,
      docCryptKeyPair.privKey,
      this.clientSignKeyPair
    )

    const actions: readonly [NRCreateDocumentAction] = [
      {
        payload: {
          creatorId: this.accountId,
          cryptAccountId: this.accountId,

          cryptPubKey: docCryptKeyPair.pubKey,
          encCryptPrivKey
        },
        type: 'CreateDocument'
      }
    ]

    const response = await this._requestActions(actions)
    const result = response.results.find(
      ({ type }) => type === 'CreateDocument'
    )

    if (!result) {
      throw new Error('No result')
    }

    return {
      cryptKeyPair: docCryptKeyPair,
      id: (result as NRCreateDocumentResult).payload.documentId
    }
  }

  /**
   * Grant read access on a document to a group or individual account
   *
   * @param documentId unique identifier of the document to grant access to
   * @param kind what type of grant this is, a group or an individual account
   * @param id the unique identifier of the group or account to grant access to
   */
  public async grantReadAccess(
    documentId: string,
    kind: NRGrantKind,
    id: string
  ): Promise<void> {
    const granteePubKey = await this._getEncryptionPublicKey(kind, id)
    const docCryptPrivKey = await this._decryptDocumentEncryptionKey(documentId)
    const encCryptPrivKey = await this.service.primitives.encrypt(
      granteePubKey,
      docCryptPrivKey,
      this.clientSignKeyPair
    )
    const actions: readonly [NRGrantAccessAction] = [
      {
        payload: {
          documentId,
          encCryptPrivKey,
          id,
          kind
        },
        type: 'GrantAccess'
      }
    ]

    await this._requestActions(actions)
  }

  /**
   * Grant sign access on a document to a group or individual account
   *
   * @param documentId unique identifier of the document to grant access to
   * @param kind what type of grant this is, a group or an individual account
   * @param id the unique identifier of the group or account to grant access to
   */
  public async grantSignAccess(
    documentId: string,
    kind: NRGrantKind,
    id: string
  ): Promise<void> {
    const actions: readonly [NRGrantAccessAction] = [
      {
        payload: {
          canSign: true,
          documentId,
          id,
          kind
        },
        type: 'GrantAccess'
      }
    ]
    await this._requestActions(actions)
  }

  /**
   * Revoke access on a document from a group or individual account
   *
   * @param documentId unique identifier of the document to grant access to
   * @param kind what type of grant this is, a group or an individual account
   * @param id the unique identifier of the group or account to grant access to
   */
  public async revokeAccess(
    documentId: string,
    kind: NRGrantKind,
    id: string
  ): Promise<void> {
    const actions: readonly [NRRevokeAccessAction] = [
      {
        payload: {
          documentId,
          id,
          kind
        },
        type: 'RevokeAccess'
      }
    ]

    await this._requestActions(actions)
  }

  /**
   * Sign an array of pre-hashed values on a document in natural rights
   *
   * @param documentId unique identifier of the document to sign texts on
   * @param hashes array of hashes to sign
   * @returns a corresponding array of signatures
   */
  public async signDocumentHashes(
    documentId: string,
    hashes: readonly string[]
  ): Promise<readonly string[]> {
    const actions: readonly [NRSignDocumentAction] = [
      {
        payload: {
          documentId,
          hashes
        },
        type: 'SignDocument'
      }
    ]
    const response = await this._requestActions(actions)
    const result = response.results.find(({ type }) => type === 'SignDocument')
    if (!result) {
      throw new Error('No SignDocument result')
    }
    return (result as NRSignDocumentResult).payload.signatures
  }

  /**
   * Sign an array of texts on a document in natural rights
   *
   * @param documentId unique identifier of the document to sign texts on
   * @param textsToSign array of strings to sign
   * @returns a corresponding array of signatures
   */
  public async signDocumentTexts(
    documentId: string,
    textsToSign: readonly string[]
  ): Promise<readonly string[]> {
    const hashes = await Promise.all(
      textsToSign.map<Promise<string>>(hashForSignature)
    )
    return this.signDocumentHashes(documentId, hashes)
  }

  /**
   * Decrypt an array of texts from a document in natural rights
   *
   * @param documentId unique identifier of the document to decrypt texts from
   * @param ciphertexts array of ciphertexts to decrypt
   * @returns a corresponding array of plaintexts
   */
  public async decryptDocumentTexts(
    documentId: string,
    ciphertexts: readonly string[]
  ): Promise<readonly string[]> {
    const privKey = await this._decryptDocumentEncryptionKey(documentId)
    return Promise.all(
      ciphertexts.map(ciphertext => decrypt(ciphertext, privKey))
    )
  }

  /**
   * Encrypt an array of texts for a document in natural rights
   *
   * @param documentId unique identifier of the document to encrypt texts for
   * @param plaintexts array of plaintexts to encrypt
   */
  public async encryptDocumentTexts(
    documentId: string,
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
    const privKey = await this._decryptDocumentEncryptionKey(documentId)
    if (!privKey) {
      throw new Error('No document access')
    }
    return Promise.all(
      plaintexts.map<
        Promise<
          | string
          | {
              readonly ct: any
              readonly iv: any
              readonly s: any
            }
        >
      >(text => encrypt(text, privKey))
    )
  }

  protected async _getPublicKeys(
    kind: NRSignatureKind,
    id: string
  ): Promise<NRGetPubKeysResultPayload> {
    const actions: readonly [NRGetPubKeysAction] = [
      {
        payload: {
          id,
          kind
        },
        type: 'GetPubKeys'
      }
    ]
    const response = await this._requestActions(actions)

    const result = response.results.find(({ type }) => type === 'GetPubKeys')
    if (!result) {
      throw new Error('No GetPubKeys result')
    }

    return (result as NRGetPubKeysResult).payload
  }

  protected async _updateDocumentEncryption(
    documentId: string
  ): Promise<NRKeyPair> {
    const accountPubKey = await this._getEncryptionPublicKey(
      'account',
      this.accountId
    )
    const docCryptKeyPair = await this.service.primitives.cryptKeyGen()
    const encCryptPrivKey = await this.service.primitives.encrypt(
      accountPubKey,
      docCryptKeyPair.privKey,
      this.clientSignKeyPair
    )
    const actions: readonly [NRUpdateDocumentAction] = [
      {
        payload: {
          cryptAccountId: this.accountId,
          cryptPubKey: docCryptKeyPair.pubKey,
          documentId,
          encCryptPrivKey
        },
        type: 'UpdateDocument'
      }
    ]
    await this._requestActions(actions)
    return docCryptKeyPair
  }

  protected async _decryptDocumentEncryptionKey(
    documentId: string
  ): Promise<string> {
    const actions: readonly [NRDecryptDocumentAction] = [
      {
        payload: {
          documentId
        },
        type: 'DecryptDocument'
      }
    ]
    const response = await this._requestActions(actions)
    const result = response.results.find(
      ({ type }) => type === 'DecryptDocument'
    )
    if (!result) {
      throw new Error('No DecryptDocument result')
    }
    const { encCryptPrivKey } = (result as NRDecryptDocumentResult).payload
    const cryptPrivKey = this.service.primitives.decrypt(
      this.clientCryptKeyPair,
      encCryptPrivKey
    )
    return cryptPrivKey
  }

  protected async _getKeyPairs(
    kind: NRSignatureKind,
    id: string
  ): Promise<NRGetKeyPairsResultPayload> {
    const response = await this._requestActions([
      {
        payload: {
          id,
          kind
        },
        type: 'GetKeyPairs'
      }
    ] as readonly [NRGetKeyPairsAction])

    const result = response.results.find(
      ({ type }: NRResult) => type === 'GetKeyPairs'
    )
    if (!result) {
      throw new Error('No GetKeyPairs result')
    }

    return result.payload as NRGetKeyPairsResultPayload
  }

  protected async _getEncryptionPublicKey(
    kind: NRGrantKind,
    id: string
  ): Promise<string> {
    const keys = await this._getPublicKeys(kind, id)
    return keys.cryptPubKey
  }

  protected async _getEncryptionKeyPair(
    kind: NRGrantKind,
    id: string
  ): Promise<NRKeyPair> {
    const pairs = await this._getKeyPairs(kind, id)

    return {
      privKey: await this.service.primitives.decrypt(
        this.clientCryptKeyPair,
        pairs.encCryptPrivKey
      ),
      pubKey: pairs.cryptPubKey
    }
  }

  protected async _requestActions(
    actions: readonly NRAction[]
  ): Promise<NRResponse> {
    const request = await this._signRequest(actions)
    const response = await this.service.request(request)
    const errors = getErrors(response)
    if (errors.length) {
      throw errors
    }
    return response
  }

  protected async _signRequest(
    actions: readonly NRAction[]
  ): Promise<NRRequest> {
    const body = JSON.stringify(actions)
    const signature = await this.service.primitives.sign(
      this.clientSignKeyPair,
      body
    )
    return {
      body,
      clientId: this.clientId,
      signature
    }
  }
}

function getErrors(response: NRResponse): readonly NRResult[] {
  return response.results.filter(result => !!result.error)
}
