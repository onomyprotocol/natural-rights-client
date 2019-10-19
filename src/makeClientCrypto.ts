import {
  NRAction,
  NRClientCrypto,
  NRKeyPair,
  PREPrimitivesInterface
} from '@natural-rights/common'
import { decrypt, encrypt, pair as createPairs } from '@notabug/gun-sear'

export function makeClientCrypto(
  primitives: PREPrimitivesInterface,
  {
    clientSignKeyPair,
    clientCryptKeyPair
  }: {
    clientSignKeyPair: NRKeyPair
    clientCryptKeyPair: NRKeyPair
  }
): NRClientCrypto {
  const clientCrypto = {
    clientCryptPubKey: clientCryptKeyPair.pubKey,
    clientSignPubKey: clientSignKeyPair.pubKey,

    publicKeys: () => {
      return {
        clientCryptPubKey: clientCryptKeyPair.pubKey,
        clientSignPubKey: clientSignKeyPair.pubKey
      }
    },

    /**
     * Sign one or more NRAction's with this account or client
     */
    signRequest: async ({
      actions
    }: {
      readonly actions: readonly NRAction[]
    }) => {
      const body = JSON.stringify(actions)
      const signature = await primitives.sign(clientSignKeyPair, body)
      return {
        body,
        clientId: clientSignKeyPair.pubKey,
        signature
      }
    },

    /**
     * Authorize a client on an account
     */
    createClientAuth: async ({
      accountCryptPubKey,
      accountEncCryptPrivKey,
      clientCryptPubKey
    }: {
      readonly accountCryptPubKey: string
      readonly clientCryptPubKey: string
      readonly accountEncCryptPrivKey: string
    }) => {
      return {
        clientCryptTransformKey: await primitives.cryptTransformKeyGen(
          {
            privKey: await primitives.decrypt(
              clientCryptKeyPair,
              accountEncCryptPrivKey
            ),
            pubKey: accountCryptPubKey
          },
          clientCryptPubKey,
          clientSignKeyPair
        )
      }
    },

    /**
     * Return account credentials to register with service
     *
     * May go away after next refactor stage and can be ignored by companion
     */
    createAccount: async () => {
      const accountCryptKeyPair = await primitives.cryptKeyGen()
      const accountSignKeyPair = await primitives.signKeyGen()

      const accountEncCryptPrivKey = await primitives.encrypt(
        accountCryptKeyPair.pubKey,
        accountCryptKeyPair.privKey,
        clientSignKeyPair
      )

      const accountEncSignPrivKey = await primitives.encrypt(
        accountCryptKeyPair.pubKey,
        accountSignKeyPair.privKey,
        clientSignKeyPair
      )

      const clientCryptTransformKey = await primitives.cryptTransformKeyGen(
        accountCryptKeyPair,
        clientCryptKeyPair.pubKey,
        accountSignKeyPair
      )

      return {
        accountCryptPubKey: accountCryptKeyPair.pubKey,
        accountEncCryptPrivKey,
        accountEncSignPrivKey,
        accountSignPubKey: accountSignKeyPair.pubKey,
        clientCryptTransformKey
      }
    },

    /**
     * Generate and encrypt keypair for a document
     */
    createDocument: async ({
      accountCryptPubKey
    }: {
      accountCryptPubKey: string
    }) => {
      const pairs = await createPairs()

      const docCryptKeyPair = {
        privKey: pairs.epriv,
        pubKey: pairs.epub
      }

      const documentEncCryptPrivKey = await primitives.encrypt(
        accountCryptPubKey,
        docCryptKeyPair.privKey,
        clientSignKeyPair
      )

      return {
        documentCryptPubKey: docCryptKeyPair.pubKey,
        documentEncCryptPrivKey
      }
    },

    /**
     * Generate an encrypted document private key for the grantee
     */
    createGrant: async ({
      granteeCryptPubKey,
      documentEncCryptPrivKey
    }: {
      readonly granteeCryptPubKey: string
      readonly documentEncCryptPrivKey: string
    }) => {
      const documentCryptPrivKey = await primitives.decrypt(
        clientCryptKeyPair,
        documentEncCryptPrivKey
      )
      const documentEncCryptPrivKeyForGrantee = await primitives.encrypt(
        granteeCryptPubKey,
        documentCryptPrivKey,
        clientSignKeyPair
      )
      return { documentEncCryptPrivKeyForGrantee }
    },

    /**
     * Generate and encrypt keypairs for a group
     */
    createGroup: async ({
      accountCryptPubKey
    }: {
      readonly accountCryptPubKey: string
    }) => {
      const groupCryptKeyPair = await primitives.cryptKeyGen()
      const groupSignKeyPair = await primitives.signKeyGen()

      const groupEncCryptPrivKey = await primitives.encrypt(
        accountCryptPubKey,
        groupCryptKeyPair.privKey,
        clientSignKeyPair
      )

      const groupEncSignPrivKey = await primitives.encrypt(
        accountCryptPubKey,
        groupSignKeyPair.privKey,
        clientSignKeyPair
      )

      const memberCryptTransformKey = await primitives.cryptTransformKeyGen(
        groupCryptKeyPair,
        accountCryptPubKey,
        groupSignKeyPair
      )

      return {
        groupCryptPubKey: groupCryptKeyPair.pubKey,
        groupEncCryptPrivKey,
        groupEncSignPrivKey,
        groupSignPubKey: groupSignKeyPair.pubKey,
        memberCryptTransformKey
      }
    },

    /**
     * Generate transform key and optional encrypted private key for group member
     */
    createMembership: async ({
      groupCryptPubKey,
      groupEncCryptPrivKey,
      memberCryptPubKey,
      admin
    }: {
      readonly groupCryptPubKey: string
      readonly groupEncCryptPrivKey: string
      readonly memberCryptPubKey: string
      readonly admin?: boolean
    }) => {
      const groupCryptPrivKey = await primitives.decrypt(
        clientCryptKeyPair,
        groupEncCryptPrivKey
      )
      const groupCryptKeyPair = {
        privKey: groupCryptPrivKey,
        pubKey: groupCryptPubKey
      }
      const memberCryptTransformKey = await primitives.cryptTransformKeyGen(
        groupCryptKeyPair,
        memberCryptPubKey,
        clientSignKeyPair
      )
      const encCryptPrivKey = admin
        ? await primitives.encrypt(
            memberCryptPubKey,
            groupCryptPrivKey,
            clientSignKeyPair
          )
        : ''

      return {
        encCryptPrivKey,
        memberCryptTransformKey
      }
    },

    /**
     * Decrypt a collection of ciphertexts from a given document
     */
    decryptDocumentTexts: async ({
      ciphertexts,
      documentEncCryptPrivKey
    }: {
      ciphertexts: readonly string[]
      documentEncCryptPrivKey: string
    }) => {
      const cryptPrivKey = await primitives.decrypt(
        clientCryptKeyPair,
        documentEncCryptPrivKey
      )

      return {
        plaintexts: await Promise.all(
          ciphertexts.map(ciphertext => decrypt(ciphertext, cryptPrivKey))
        )
      }
    },

    /**
     * Encrypt a collection of ciphertexts for a given document
     */
    encryptDocumentTexts: async ({
      documentEncCryptPrivKey,
      plaintexts
    }: {
      readonly plaintexts: readonly string[]
      readonly documentEncCryptPrivKey: string
    }) => {
      const cryptPrivKey = await primitives.decrypt(
        clientCryptKeyPair,
        documentEncCryptPrivKey
      )

      return {
        ciphertexts: await Promise.all(
          plaintexts.map(plaintext => encrypt(plaintext, cryptPrivKey))
        )
      }
    }
  }

  // @ts-ignore
  return clientCrypto
}
