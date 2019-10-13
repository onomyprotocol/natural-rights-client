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
    cryptPubKey: clientCryptKeyPair.pubKey,

    createAccount: async () => {
      const accountCryptKeyPair = await primitives.cryptKeyGen()
      const accountSignKeyPair = await primitives.signKeyGen()
      const encCryptPrivKey = await clientCrypto.encryptKey(
        accountCryptKeyPair.pubKey,
        accountCryptKeyPair.privKey
      )
      const encSignPrivKey = await clientCrypto.encryptKey(
        accountCryptKeyPair.pubKey,
        accountSignKeyPair.privKey
      )
      const cryptTransformKey = await primitives.cryptTransformKeyGen(
        accountCryptKeyPair,
        clientCrypto.cryptPubKey,
        accountSignKeyPair
      )

      return {
        cryptPubKey: accountCryptKeyPair.pubKey,
        cryptTransformKey,
        encCryptPrivKey,
        encSignPrivKey,
        signPubKey: accountSignKeyPair.pubKey
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

      const encCryptPrivKey = await primitives.encrypt(
        accountCryptPubKey,
        docCryptKeyPair.privKey,
        clientSignKeyPair
      )

      return {
        encCryptPrivKey
      }
    },

    cryptTransformKeyGen: (toCryptPubKey: string) =>
      primitives.cryptTransformKeyGen(
        clientCryptKeyPair,
        toCryptPubKey,
        clientSignKeyPair
      ),

    decryptKey: (ciphertext: string) =>
      primitives.decrypt(clientCryptKeyPair, ciphertext),

    decryptDocumentTexts: async ({
      ciphertexts,
      encPrivKey
    }: {
      ciphertexts: readonly string[]
      encPrivKey: string
    }) => {
      const cryptPrivKey = await clientCrypto.decryptKey(encPrivKey)

      return Promise.all(
        ciphertexts.map(ciphertext => decrypt(ciphertext, cryptPrivKey))
      )
    },

    encryptKey: (pubKey: string, plaintext: string) =>
      primitives.encrypt(pubKey, plaintext, clientSignKeyPair),

    encryptDocumentTexts: async ({
      accountCryptPubKey,
      plaintexts,
      encCryptPrivKey
    }: {
      accountCryptPubKey: string
      plaintexts: readonly string[]
      cryptPubKey?: string
      encCryptPrivKey?: string
    }) => {
      const cryptPrivKey = await _getCryptPrivKey({
        accountCryptPubKey,
        encCryptPrivKey
      })

      return Promise.all(
        plaintexts.map(plaintext => encrypt(plaintext, cryptPrivKey))
      )
    },

    sign: (text: string) => primitives.sign(clientSignKeyPair, text),

    signPubKey: clientCryptKeyPair.pubKey
  }

  async function _getCryptPrivKey({
    accountCryptPubKey,
    encCryptPrivKey
  }: {
    accountCryptPubKey: string
    encCryptPrivKey?: string
  }): Promise<string> {
    if (encCryptPrivKey) {
      return clientCrypto.decryptKey(encCryptPrivKey)
    } else {
      return (await clientCrypto.createDocument({
        accountCryptPubKey
      })).encCryptPrivKey
    }
  }

  // @ts-ignore
  return clientCrypto
}
