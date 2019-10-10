import {
  NRRequest,
  NRResponse,
  NRServiceInterface,
  PREPrimitivesInterface
} from '@natural-rights/common'
import 'isomorphic-fetch'

declare const fetch: any

/**
 * Sends Natural Rights requests to a remote HTTP Service
 */
export class RemoteHttpService implements NRServiceInterface {
  public readonly primitives: PREPrimitivesInterface
  public readonly url: string

  constructor(primitives: PREPrimitivesInterface, url: string) {
    this.primitives = primitives
    this.url = url
  }

  /**
   * Send a request to the remote Natural Rights service
   *
   * @param req The properly formatted and signed request to send
   */
  public async request(req: NRRequest): Promise<NRResponse> {
    const httpResponse = await fetch(this.url, {
      body: JSON.stringify(req),
      headers: {
        'Content-Type': 'application/json'
      },
      method: 'POST'
    })
    if (httpResponse.status >= 300) {
      throw new Error('Bad HTTP Response')
    }
    return httpResponse.json()
  }
}
