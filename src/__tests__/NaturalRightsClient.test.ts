// tslint:disable: no-string-literal
import {
  NRAction,
  NRErrorResult,
  NRGrantAccessAction,
  NRGrantAccessResult,
  NRServiceInterface
} from '@natural-rights/common'
import * as SEA from '@notabug/gun-sear'
import { NaturalRightsClient } from '../NaturalRightsClient'

describe('NaturalRightsClient', () => {
  let service: NRServiceInterface
  const accountId = 'testaccountid'
  const clientCryptKeyPair = {
    privKey: 'clientCryptPrivKey',
    pubKey: 'clientCryptPubKey'
  }
  const clientSignKeyPair = {
    privKey: 'clientSignPrivKey',
    pubKey: 'clientSignPubKey'
  }
  const clientId = clientSignKeyPair.pubKey

  beforeEach(() => {
    service = {
      primitives: {
        cryptKeyGen: jest.fn().mockResolvedValue({
          privKey: 'cryptPrivKey',
          pubKey: 'cryptPubKey'
        }),
        cryptTransform: jest.fn(),
        cryptTransformKeyGen: jest
          .fn()
          .mockImplementation(
            async (keyPair, pubKey) => `transform:${keyPair.privKey}:${pubKey}`
          ),
        decrypt: jest.fn(),
        encrypt: jest
          .fn()
          .mockImplementation(
            async (pubKey, plaintext) => `encrypted:${pubKey}:${plaintext}`
          ),
        sign: jest.fn(),
        signKeyGen: jest.fn().mockResolvedValue({
          privKey: 'signPrivKey',
          pubKey: 'signPubKey'
        }),
        verify: jest.fn()
      },
      request: jest.fn().mockResolvedValue({
        results: []
      })
    }
  })

  describe('sign', () => {
    it('stringifies and signs passed actions', async () => {
      const expectedSignature = 'signature'

      const signMock = jest
        .spyOn(service.primitives, 'sign')
        .mockResolvedValue(expectedSignature)

      try {
        const client = new NaturalRightsClient(
          service,
          clientCryptKeyPair,
          clientSignKeyPair
        )
        const actions: ReadonlyArray<NRAction> = [
          {
            payload: {
              documentId: '',
              id: '',
              kind: 'account'
            },
            type: 'GrantAccess'
          }
        ]

        // tslint:disable-next-line: no-string-literal
        const result = await client['_signRequest'](actions)

        expect(JSON.parse(result.body)).toEqual(actions)
        expect(result.clientId).toEqual(client.clientId)
        expect(result.signature).toEqual(expectedSignature)
        expect(service.primitives.sign).toHaveBeenCalledWith(
          clientSignKeyPair,
          result.body
        )
      } finally {
        signMock.mockRestore()
      }
    })
  })

  describe('_signRequest', () => {
    it('signs passed actions and sends request to service', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const expectedRequest = {
        accountId,
        body: '',
        clientId,
        signature: ''
      }

      // @ts-ignore
      jest.spyOn(client, '_signRequest').mockResolvedValue(expectedRequest)

      const actions: ReadonlyArray<NRGrantAccessAction> = [
        {
          payload: {
            documentId: '',
            id: '',
            kind: 'account'
          },
          type: 'GrantAccess'
        }
      ]

      await client['_requestActions'](actions)
      expect(client['_signRequest']).toHaveBeenCalledWith(actions)
      expect(service.request).toHaveBeenCalledWith(expectedRequest)
    })

    it('throws errors if encountered in response', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const errors: ReadonlyArray<NRErrorResult> = [
        {
          error: 'Some error',
          payload: {
            documentId: 'someDocId',
            id: 'someAccountId',
            kind: 'account'
          },
          success: false,
          type: 'GrantAccess'
        }
      ]
      const successes: ReadonlyArray<NRGrantAccessResult> = [
        {
          error: '',
          payload: {
            documentId: 'someDocId',
            id: 'someAccountId',
            kind: 'account'
          },
          success: true,
          type: 'GrantAccess'
        }
      ]

      const serviceRequestMock = jest
        .spyOn(service, 'request')
        .mockResolvedValue({
          results: [...errors, ...successes]
        })

      try {
        let success = false

        try {
          await client['_requestActions']([])
          success = true
        } catch (e) {
          expect(e).toEqual(errors)
        }

        expect(success).toEqual(false)
      } finally {
        serviceRequestMock.mockRestore()
      }
    })
  })

  describe('registerAccount', () => {
    let client: NaturalRightsClient

    beforeEach(() => {
      client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.login = jest.fn().mockResolvedValue({
        accountId,
        rootDocumentId: 'rootDocumentId'
      })
    })

    it('uses cryptKeyGen to generate encryption key pair', async () => {
      await client.registerAccount()
      expect(service.primitives.cryptKeyGen).toHaveBeenCalled()
    })

    it('uses signKeyGen to generate signing key pair', async () => {
      await client.registerAccount()
      expect(service.primitives.cryptKeyGen).toHaveBeenCalled()
    })

    it('uses Encrypt to encrypt private keys', async () => {
      await client.registerAccount()
      expect(service.primitives.encrypt).toHaveBeenCalledWith(
        'cryptPubKey',
        'signPrivKey',
        clientSignKeyPair
      )
      expect(service.primitives.encrypt).toHaveBeenCalledWith(
        'cryptPubKey',
        'cryptPrivKey',
        clientSignKeyPair
      )
    })

    it('makes a request including accountId, public keys and encrypted private keys', async () => {
      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      const accountSignKeyPair = {
        privKey: 'accountSignPrivKey',
        pubKey: 'accountSignPubKey'
      }

      const signKeyGenMock = jest
        .spyOn(service.primitives, 'signKeyGen')
        .mockResolvedValue(accountSignKeyPair)

      try {
        await client.registerAccount()

        expect(client['_requestActions']).toHaveBeenCalledWith([
          {
            payload: {
              accountId: accountSignKeyPair.pubKey,
              cryptPubKey: 'cryptPubKey',
              encCryptPrivKey: 'encrypted:cryptPubKey:cryptPrivKey',
              encSignPrivKey: `encrypted:cryptPubKey:${accountSignKeyPair.privKey}`,
              rootDocCryptPubKey: 'cryptPubKey',
              rootDocEncCryptPrivKey: 'encrypted:cryptPubKey:cryptPrivKey',
              signPubKey: accountSignKeyPair.pubKey
            },
            type: 'InitializeAccount'
          },
          {
            payload: {
              accountId: accountSignKeyPair.pubKey,
              clientId,
              cryptTransformKey: 'transform:cryptPrivKey:clientCryptPubKey'
            },
            type: 'AuthorizeClient'
          }
        ])
      } finally {
        signKeyGenMock.mockRestore()
      }
    })
  })

  describe('deauthorizeAccount', () => {
    it('makes a request including accountId and clientId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const toRemoveId = 'removeClientId'

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.deauthorizeClient(toRemoveId)
      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            accountId,
            clientId: toRemoveId
          },
          type: 'DeauthorizeClient'
        }
      ])
    })
  })

  describe('createGroup', () => {
    it('uses KeyGen to generate encryption key pair', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const accountPubKey = 'accountEncPubKey'

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(accountPubKey)

      await client.createGroup()

      expect(service.primitives.cryptKeyGen).toHaveBeenCalled()
    })

    it('encrypts private key to owning account pub key', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const accountPubKey = 'accountEncPubKey'

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(accountPubKey)

      await client.createGroup()
      expect(service.primitives.encrypt).toHaveBeenCalledWith(
        accountPubKey,
        'cryptPrivKey',
        clientSignKeyPair
      )
    })

    it('makes a request with publicKey, accountId, encryptedPrivateKey', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const accountPubKey = 'accountCryptPubKey'

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(accountPubKey)

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      const expectedSignKeyPair = {
        privKey: 'groupSignPrivKey',
        pubKey: 'groupSignPubKey'
      }

      const signKeyGenMock = jest
        .spyOn(client.service.primitives, 'signKeyGen')
        .mockResolvedValue(expectedSignKeyPair)

      try {
        const groupId = await client.createGroup()
        expect(client['_getEncryptionPublicKey']).toHaveBeenCalledWith(
          'account',
          accountId
        )
        expect(client['_requestActions']).toHaveBeenCalledWith([
          {
            payload: {
              accountId,
              cryptPubKey: 'cryptPubKey',
              encCryptPrivKey: 'encrypted:accountCryptPubKey:cryptPrivKey',
              encSignPrivKey: `encrypted:${accountPubKey}:${expectedSignKeyPair.privKey}`,
              groupId
            },
            type: 'CreateGroup'
          },
          {
            payload: {
              accountId,
              canSign: true,
              cryptTransformKey: 'transform:cryptPrivKey:accountCryptPubKey',
              groupId
            },
            type: 'AddMemberToGroup'
          },
          {
            payload: {
              accountId,
              encCryptPrivKey: 'encrypted:accountCryptPubKey:cryptPrivKey',
              groupId
            },
            type: 'AddAdminToGroup'
          }
        ])
      } finally {
        signKeyGenMock.mockRestore()
      }
    })
  })

  describe('addReaderToGroup', () => {
    it('uses cryptTransformKeyGen for Group->Member to build cryptTransformKey', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const groupId = 'testgroupid'
      const memberId = 'memberaccountid'
      const memberPubKey = 'memberCryptPubKey'
      const groupCryptKeyPair = {
        privKey: 'groupCryptPrivKey',
        pubKey: 'groupCryptPubKey'
      }

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(memberPubKey)

      // @ts-ignore
      const getPairMock = jest.spyOn(client, '_getEncryptionKeyPair')
      getPairMock.mockResolvedValue(groupCryptKeyPair)

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.addReaderToGroup(groupId, memberId)

      expect(client['_getEncryptionPublicKey']).toHaveBeenCalledWith(
        'account',
        memberId
      )
      expect(client['_getEncryptionKeyPair']).toHaveBeenCalledWith(
        'group',
        groupId
      )
      expect(
        client.service.primitives.cryptTransformKeyGen
      ).toHaveBeenCalledWith(groupCryptKeyPair, memberPubKey, clientSignKeyPair)

      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            accountId: memberId,
            cryptTransformKey: 'transform:groupCryptPrivKey:memberCryptPubKey',
            groupId
          },
          type: 'AddMemberToGroup'
        }
      ])
    })
  })

  describe('removeMemberFromGroup', () => {
    it('makes a request including requesting accountId and groupId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const toRemoveId = 'removeMemberId'
      const groupId = 'groupId'

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.removeMemberFromGroup(groupId, toRemoveId)
      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            accountId: toRemoveId,
            groupId
          },
          type: 'RemoveMemberFromGroup'
        }
      ])
    })

    describe('when removing a member referenced as signTransformParentAccountId for other accounts', () => {
      it.todo(
        'includes AddMemberToGroup for each affected membership to maintain write access'
      )
    })
  })

  describe('addAdminToGroup', () => {
    it('makes a request including accountId, groupId, and encrypted private keys', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const memberPubKey = 'memberCryptPubKey'
      const groupCryptKeyPair = {
        privKey: 'groupCryptPrivKey',
        pubKey: 'groupCryptPubKey'
      }

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(memberPubKey)

      // @ts-ignore
      const getPairMock = jest.spyOn(client, '_getEncryptionKeyPair')
      getPairMock.mockResolvedValue(groupCryptKeyPair)
      const toAddId = 'addMemberId'
      const groupId = 'groupId'

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.addAdminToGroup(groupId, toAddId)

      expect(client['_getEncryptionPublicKey']).toHaveBeenCalledWith(
        'account',
        toAddId
      )
      expect(client['_getEncryptionKeyPair']).toHaveBeenCalledWith(
        'group',
        groupId
      )
      expect(client.service.primitives.encrypt).toHaveBeenCalledWith(
        memberPubKey,
        groupCryptKeyPair.privKey,
        clientSignKeyPair
      )
      expect(
        client.service.primitives.cryptTransformKeyGen
      ).toHaveBeenCalledWith(groupCryptKeyPair, memberPubKey, clientSignKeyPair)

      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            accountId: toAddId,
            canSign: true,
            cryptTransformKey: 'transform:groupCryptPrivKey:memberCryptPubKey',
            groupId
          },
          type: 'AddMemberToGroup'
        },
        {
          payload: {
            accountId: toAddId,
            encCryptPrivKey: 'encrypted:memberCryptPubKey:groupCryptPrivKey',
            groupId
          },
          type: 'AddAdminToGroup'
        }
      ])
    })
  })

  describe('removeAdminFromGroup', () => {
    it('makes a request including accountId and groupId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const toRemoveId = 'removeAdminId'
      const groupId = 'groupId'

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.removeAdminFromGroup(groupId, toRemoveId)

      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            accountId: toRemoveId,
            groupId
          },
          type: 'RemoveAdminFromGroup'
        }
      ])
    })
  })

  describe('createDocument', () => {
    it('generates an encryption keypair and registers it with service', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const accountPubKey = 'accountPubKey'
      const expectedCryptKeyPair = {
        privKey: 'cryptPrivKey',
        pubKey: 'cryptPubKey'
      }
      const expectedSignKeyPair = {
        privKey: 'docSignPrivKey',
        pubKey: 'docSignPubKey'
      }
      const documentId = expectedSignKeyPair.pubKey

      // @ts-ignore
      const pairMock = jest.spyOn(SEA, 'pair').mockResolvedValue({
        epriv: expectedCryptKeyPair.privKey,
        epub: expectedCryptKeyPair.pubKey,
        priv: expectedSignKeyPair.privKey,
        pub: expectedSignKeyPair.pubKey
      })

      try {
        // @ts-ignore
        const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
        getKeyMock.mockResolvedValue(accountPubKey)

        // @ts-ignore
        const reqMock = jest.spyOn(client, '_requestActions')
        reqMock.mockResolvedValue({
          results: [
            {
              payload: {
                documentId
              },
              type: 'CreateDocument'
            }
          ]
        })

        const doc = await client.createDocument()

        expect(SEA.pair).toHaveBeenCalled()
        expect(doc.cryptKeyPair).toEqual(expectedCryptKeyPair)
        expect(doc.id).toEqual(documentId)
        expect(client.service.primitives.encrypt).toHaveBeenCalledWith(
          accountPubKey,
          expectedCryptKeyPair.privKey,
          clientSignKeyPair
        )

        expect(client['_requestActions']).toHaveBeenCalledWith([
          {
            payload: {
              creatorId: accountId,
              cryptAccountId: accountId,

              cryptPubKey: expectedCryptKeyPair.pubKey,
              encCryptPrivKey: 'encrypted:accountPubKey:cryptPrivKey'
            },
            type: 'CreateDocument'
          }
        ])
      } finally {
        pairMock.mockRestore()
      }
    })
  })

  describe('grantReadAccess', () => {
    it('makes a request including documentId, encrypted decryption key and accountId or groupId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const documentId = 'testDocumentId'
      const granteeId = 'testGranteeId'
      const granteeKind = 'account'
      const granteePubKey = 'granteePubKey'
      const docCryptPrivKey = 'decryptedDocumentCryptPrivKey'

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(granteePubKey)

      // @ts-ignore
      const getDecKeyMock = jest.spyOn(client, '_decryptDocumentEncryptionKey')
      getDecKeyMock.mockResolvedValue(docCryptPrivKey)

      // @ts-ignore
      client._requestActions = jest.fn().mockResolvedValue({
        results: []
      })

      await client.grantReadAccess(documentId, granteeKind, granteeId)

      expect(client['_getEncryptionPublicKey']).toHaveBeenCalledWith(
        granteeKind,
        granteeId
      )
      expect(client['_decryptDocumentEncryptionKey']).toHaveBeenCalledWith(
        documentId
      )
      expect(service.primitives.encrypt).toHaveBeenCalledWith(
        granteePubKey,
        docCryptPrivKey,
        clientSignKeyPair
      )

      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            documentId,
            encCryptPrivKey: `encrypted:${granteePubKey}:${docCryptPrivKey}`,
            id: granteeId,
            kind: granteeKind
          },
          type: 'GrantAccess'
        }
      ])
    })
  })

  describe('decryptDocumentKey', () => {
    it('makes a request including documentId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const documentId = 'testDocumentId'
      const encCryptPrivKey = 'documentEncCryptPrivKey'
      const cryptPrivKey = 'decryptedDocumentCryptPrivKey'

      const decryptMock = jest
        .spyOn(client.service.primitives, 'decrypt')
        .mockResolvedValue(cryptPrivKey)

      // @ts-ignore
      const reqMock = jest.spyOn(client, '_requestActions')
      reqMock.mockResolvedValue({
        results: [
          {
            payload: {
              accountId,
              documentId,
              encCryptPrivKey
            },
            type: 'DecryptDocument'
          }
        ]
      })

      try {
        const documentCryptPrivKey = await client[
          '_decryptDocumentEncryptionKey'
        ](documentId)

        expect(client['_requestActions']).toHaveBeenCalledWith([
          {
            payload: {
              documentId
            },
            type: 'DecryptDocument'
          }
        ])
        expect(client.service.primitives.decrypt).toHaveBeenCalledWith(
          clientCryptKeyPair,
          encCryptPrivKey
        )
        expect(documentCryptPrivKey).toEqual(cryptPrivKey)

        // @ts-ignore
        reqMock.mockResolvedValue({
          results: []
        })

        let success = false
        try {
          await client['_decryptDocumentEncryptionKey'](documentId)
          success = true
        } catch (e) {
          expect(e).toEqual(new Error('No DecryptDocument result'))
        }

        expect(success).toEqual(false)
      } finally {
        decryptMock.mockRestore()
      }
    })
  })

  describe('revokeAccess', () => {
    it('makes a request including documentId and accountId', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const toRemoveId = 'removeAdminId'
      const documentId = 'documentId'

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      await client.revokeAccess(documentId, 'account', toRemoveId)
      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            documentId,
            id: toRemoveId,
            kind: 'account'
          },
          type: 'RevokeAccess'
        }
      ])
    })

    describe('when revoking access for a account referenced  as signTransformParentAccountId for other accounts', () => {
      it.todo(
        'includes GrantAccess for each affected grant to maintain write access'
      )
    })
  })

  describe('updateDocument', () => {
    it('generates an encryption keypair and registers it with service', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      client.accountId = accountId
      const accountPubKey = 'accountPubKey'
      const documentId = 'testdocumentid'
      const expectedCryptKeyPair = {
        privKey: 'cryptPrivKey',
        pubKey: 'cryptPubKey'
      }

      // @ts-ignore
      const getKeyMock = jest.spyOn(client, '_getEncryptionPublicKey')
      getKeyMock.mockResolvedValue(accountPubKey)

      // @ts-ignore
      jest.spyOn(client, '_requestActions').mockResolvedValue({
        results: []
      })

      const docCryptKeyPair = await client['_updateDocumentEncryption'](
        documentId
      )

      expect(client.service.primitives.cryptKeyGen).toHaveBeenCalled()
      expect(docCryptKeyPair).toEqual(expectedCryptKeyPair)
      expect(client.service.primitives.encrypt).toHaveBeenCalledWith(
        accountPubKey,
        docCryptKeyPair.privKey,
        clientSignKeyPair
      )

      expect(client['_requestActions']).toHaveBeenCalledWith([
        {
          payload: {
            cryptAccountId: accountId,
            cryptPubKey: expectedCryptKeyPair.pubKey,
            documentId,
            encCryptPrivKey: 'encrypted:accountPubKey:cryptPrivKey'
          },
          type: 'UpdateDocument'
        }
      ])
    })
  })

  describe('getPublicKeys', () => {
    it('makes a request asking for public keys', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const testAccountId = 'testAccountId'
      const cryptPubKey = 'accountCryptPubKey'
      const signPubKey = 'accountSignPubKey'

      const payload = {
        id: testAccountId,
        kind: 'account'
      }

      // @ts-ignore
      const reqMock = jest.spyOn(client, '_requestActions')
      reqMock.mockResolvedValue({
        results: [
          {
            error: '',
            payload: {
              ...payload,
              cryptPubKey,
              signPubKey
            },
            success: true,
            type: 'GetPubKeys'
          }
        ]
      })

      expect(await client['_getPublicKeys']('account', testAccountId)).toEqual({
        ...payload,
        cryptPubKey,
        signPubKey
      })

      reqMock.mockResolvedValue({
        results: []
      })

      let success = false
      try {
        await client['_getPublicKeys']('account', testAccountId)
        success = true
      } catch (e) {
        expect(e).toEqual(new Error('No GetPubKeys result'))
      }

      expect(success).toEqual(false)
    })
  })

  describe('getKeyPairs', () => {
    it('makes a request asking for key pairs', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const testAccountId = 'testAccountId'
      const cryptPubKey = 'accountCryptPubKey'
      const signPubKey = 'accountSignPubKey'
      const encCryptPrivKey = 'clientEncCryptPrivKey'
      const encSignPrivKey = 'clientEncSignPrivKey'

      const payload = {
        id: testAccountId,
        kind: 'account'
      }

      // @ts-ignore
      const reqMock = jest.spyOn(client, '_requestActions')
      reqMock.mockResolvedValue({
        results: [
          {
            error: '',
            payload: {
              ...payload,
              cryptPubKey,
              encCryptPrivKey,
              encSignPrivKey,
              signPubKey
            },
            success: true,
            type: 'GetKeyPairs'
          }
        ]
      })

      expect(await client['_getKeyPairs']('account', testAccountId)).toEqual({
        ...payload,
        cryptPubKey,
        encCryptPrivKey,
        encSignPrivKey,
        signPubKey
      })

      // @ts-ignore
      reqMock.mockResolvedValue({
        results: []
      })

      let success = false
      try {
        await client['_getKeyPairs']('account', testAccountId)
        success = true
      } catch (e) {
        expect(e).toEqual(new Error('No GetKeyPairs result'))
      }

      expect(success).toEqual(false)
    })
  })

  describe('getEncryptionPublicKey', () => {
    it('resolves encryption public key if available', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const testAccountId = 'testAccountId'
      const cryptPubKey = 'accountCryptPubKey'
      const signPubKey = 'accountSignPubKey'

      const pubKeys = {
        cryptPubKey,
        signPubKey
      }

      // @ts-ignore
      jest.spyOn(client, '_getPublicKeys').mockResolvedValue(pubKeys)

      expect(
        await client['_getEncryptionPublicKey']('account', testAccountId)
      ).toEqual(cryptPubKey)
      expect(client['_getPublicKeys']).toBeCalledWith('account', testAccountId)
    })
  })

  describe('_getEncryptionKeyPair', () => {
    it('resolves encryption key pair if available', async () => {
      const client = new NaturalRightsClient(
        service,
        clientCryptKeyPair,
        clientSignKeyPair
      )
      const testAccountId = 'testAccountId'
      const cryptPubKey = 'accountCryptPubKey'
      const signPubKey = 'accountSignPubKey'
      const encCryptPrivKey = 'clientEncCryptPrivKey'
      const encSignPrivKey = 'clientEncSignPrivKey'
      const decryptedKey = 'decryptedCryptPrivKey'

      const keyPairs = {
        cryptPubKey,
        encCryptPrivKey,
        encSignPrivKey,
        signPubKey
      }

      // @ts-ignore
      jest.spyOn(client, '_getKeyPairs').mockResolvedValue(keyPairs)

      const decryptMock = jest
        .spyOn(client.service.primitives, 'decrypt')
        .mockResolvedValue(decryptedKey)

      try {
        expect(
          await client['_getEncryptionKeyPair']('account', testAccountId)
        ).toEqual({
          privKey: decryptedKey,
          pubKey: cryptPubKey
        })
        expect(client['_getKeyPairs']).toBeCalledWith('account', testAccountId)
        expect(service.primitives.decrypt).toBeCalledWith(
          clientCryptKeyPair,
          encCryptPrivKey
        )
      } finally {
        decryptMock.mockRestore()
      }
    })
  })
})
