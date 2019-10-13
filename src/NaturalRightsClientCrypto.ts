import {
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

    createAccount: async () => {
      const accountCryptKeyPair = await primitives.cryptKeyGen()
      const accountSignKeyPair = await primitives.signKeyGen()

      const accountEncCryptPrivKey = await clientCrypto.encryptKey(
        accountCryptKeyPair.pubKey,
        accountCryptKeyPair.privKey
      )

      const accountEncSignPrivKey = await clientCrypto.encryptKey(
        accountCryptKeyPair.pubKey,
        accountSignKeyPair.privKey
      )

      const {
        clientCryptTransformKey
      } = await clientCrypto.createClientAuthorization({
        accountCryptPubKey: accountCryptKeyPair.pubKey,
        accountEncCryptPrivKey,
        clientCryptPubKey: clientCryptKeyPair.pubKey
      })

      return {
        accountCryptPubKey: accountCryptKeyPair.pubKey,
        accountEncCryptPrivKey,
        accountEncSignPrivKey,
        accountSignPubKey: accountSignKeyPair.pubKey,
        clientCryptTransformKey
      }
    },

    createClientAuthorization: async ({
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
            privKey: await clientCrypto.decryptKey(accountEncCryptPrivKey),
            pubKey: accountCryptPubKey
          },
          clientCryptPubKey,
          clientSignKeyPair
        )
      }
    },

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

    decryptDocumentTexts: async ({
      ciphertexts,
      documentEncCryptPrivKey
    }: {
      ciphertexts: readonly string[]
      documentEncCryptPrivKey: string
    }) => {
      const cryptPrivKey = await clientCrypto.decryptKey(
        documentEncCryptPrivKey
      )

      return Promise.all(
        ciphertexts.map(ciphertext => decrypt(ciphertext, cryptPrivKey))
      )
    },

    decryptKey: (encKey: string) =>
      primitives.decrypt(clientCryptKeyPair, encKey),

    encryptDocumentTexts: async ({
      accountCryptPubKey,
      documentCryptPubKey: passedCryptPubKey,
      documentEncCryptPrivKey: passedEncCryptPrivKey,
      plaintexts
    }: {
      readonly accountCryptPubKey: string
      readonly documentCryptPubKey?: string
      readonly plaintexts: readonly string[]
      readonly cryptPubKey?: string
      readonly documentEncCryptPrivKey: string
    }) => {
      const {
        documentEncCryptPrivKey,
        documentCryptPubKey
      } = await _getDocKeys({
        accountCryptPubKey,
        documentCryptPubKey: passedCryptPubKey,
        documentEncCryptPrivKey: passedEncCryptPrivKey
      })
      const cryptPrivKey = await clientCrypto.decryptKey(
        documentEncCryptPrivKey
      )

      return {
        ciphertexts: await Promise.all(
          plaintexts.map(plaintext => encrypt(plaintext, cryptPrivKey))
        ),
        documentCryptPubKey,
        documentEncCryptPrivKey
      }
    },

    encryptKey: (pubKey: string, key: string) =>
      primitives.encrypt(pubKey, key, clientSignKeyPair),

    sign: (text: string) => primitives.sign(clientSignKeyPair, text)
  }

  async function _getDocKeys({
    accountCryptPubKey,
    documentCryptPubKey,
    documentEncCryptPrivKey
  }: {
    accountCryptPubKey: string
    documentCryptPubKey?: string
    documentEncCryptPrivKey?: string
  }): Promise<{
    readonly documentCryptPubKey: string
    readonly documentEncCryptPrivKey: string
  }> {
    if (documentEncCryptPrivKey && documentCryptPubKey) {
      return {
        documentCryptPubKey,
        documentEncCryptPrivKey
      }
    } else {
      return clientCrypto.createDocument({
        accountCryptPubKey
      })
    }
  }

  // @ts-ignore
  return clientCrypto
}
