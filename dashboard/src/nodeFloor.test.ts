import pkg from '../package.json'
import { nodeFloorWarning } from './nodeFloor'

describe('nodeFloorWarning', () => {
  it('warns when the host major is below the declared floor', () => {
    const message = nodeFloorWarning('>=22', 'v20.19.6')
    expect(message).not.toBeNull()
    expect(message).toContain('v20.19.6')
    expect(message).toContain('>=22')
    expect(message).toContain('dashboard/.nvmrc')
  })

  it('is silent at the floor and above it', () => {
    // The three versions CI actually runs the dashboard suite on, plus a future
    // one, so raising the floor later cannot silently start warning on them.
    for (const version of ['v22.23.2', 'v24.16.0', 'v26.8.1', 'v30.0.0']) {
      expect(nodeFloorWarning('>=22', version)).toBeNull()
    }
  })

  it('compares majors numerically rather than lexically', () => {
    // '9' > '22' as strings. A string comparison here would warn on Node 9 and
    // stay silent on it respectively — this pins the intended direction.
    expect(nodeFloorWarning('>=22', 'v9.11.2')).not.toBeNull()
    expect(nodeFloorWarning('>=9', 'v22.23.2')).toBeNull()
  })

  it('is silent when either side is unreadable', () => {
    // An absent `process` (non-Node runner) and an `engines` range with no
    // number are both packaging questions, not host problems. Warning here
    // would train readers to ignore the message.
    expect(nodeFloorWarning('>=22', undefined)).toBeNull()
    expect(nodeFloorWarning(undefined, 'v20.19.6')).toBeNull()
    expect(nodeFloorWarning('*', 'v20.19.6')).toBeNull()
    expect(nodeFloorWarning('>=22', 'not-a-version')).toBeNull()
  })

  it('accepts a version string with or without the leading v', () => {
    expect(nodeFloorWarning('>=22', '20.19.6')).not.toBeNull()
    expect(nodeFloorWarning('>=22', '22.0.0')).toBeNull()
  })

  it('agrees with the range this package actually declares', () => {
    // Guards against the floor being edited in package.json while the versions
    // the message names, and the ones asserted above, drift away from it.
    expect(nodeFloorWarning(pkg.engines.node, 'v20.19.6')).not.toBeNull()
    expect(nodeFloorWarning(pkg.engines.node, 'v22.0.0')).toBeNull()
  })
})
