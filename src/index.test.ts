import { describe, it, expect } from 'vitest'
import { SCHLOSS_SERVER_KIT_VERSION } from './index.js'

describe('scaffold', () => {
  it('exports a version placeholder', () => {
    expect(SCHLOSS_SERVER_KIT_VERSION).toBe('0.1.0')
  })
})
