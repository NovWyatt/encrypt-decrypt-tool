/** Every page of the app; the lessons share a route and are picked by the stored lesson. */
export const PAGES = [
  { name: 'AES', route: 'aes' },
  { name: 'RSA', route: 'rsa' },
  { name: 'signatures', route: 'sign' },
  { name: 'keyring', route: 'keys' },
  { name: 'ECB and CBC lesson', route: 'learn', storage: { 'edt.learn.lesson': 'modes' } },
  { name: 'AES lesson', route: 'learn', storage: { 'edt.learn.lesson': 'aes' } },
  { name: 'RSA lesson', route: 'learn', storage: { 'edt.learn.lesson': 'rsa' } },
] as const

export const LEVELS = ['basic', 'advanced'] as const
