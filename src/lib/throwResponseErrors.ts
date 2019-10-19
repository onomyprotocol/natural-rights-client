import { NRResponse } from '@natural-rights/common'

export function throwResponseErrors(response: NRResponse): void {
  const errors = response.results.filter(result => !!result.error)

  if (errors.length) {
    // throw new Error(JSON.stringify(errors))
    throw errors
  }
}
