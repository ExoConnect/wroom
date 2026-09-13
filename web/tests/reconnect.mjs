// Real Chromium + real signaling/ICE/DTLS/SRTP. See README.md for setup.
// Only creates/disposes its own incognito contexts; never touches other tabs.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'

const webUrl = process.env.WROOM_TEST_WEB_URL ?? 'http://localhost:5173'
const cdpUrl = process.env.WROOM_TEST_CDP_URL ?? 'http://127.0.0.1:9333'
const signalUrl = process.env.WROOM_TEST_SIGNALING_URL
const room = `reconnect-${randomUUID()}`
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const version = await (await fetch(`${cdpUrl}/json/version`)).json()
const socket = new WebSocket(version.webSocketDebuggerUrl)
await new Promise((resolve, reject) => {
  socket.onopen = resolve
  socket.onerror = reject
})

let nextId = 0
const pending = new Map()
const contexts = []
socket.onmessage = ({ data }) => {
  const message = JSON.parse(data)
  const request = pending.get(message.id)
  if (!request) return
  pending.delete(message.id)
  clearTimeout(request.timer)
  if (message.error) request.reject(new Error(JSON.stringify(message.error)))
  else request.resolve(message.result)
}
function call(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++nextId
    const timer = setTimeout(() => {
      pending.delete(id)
      reject(new Error(`CDP timeout: ${method}`))
    }, 10_000)
    pending.set(id, { resolve, reject, timer })
    socket.send(JSON.stringify({ id, method, params, sessionId }))
  })
}
async function evaluate(page, expression) {
  const result = await call('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  }, page)
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails))
  return result.result.value
}
async function until(label, check) {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    if (await check()) return
    await sleep(100)
  }
  throw new Error(`Timed out: ${label}`)
}
async function newPage() {
  const { browserContextId } = await call('Target.createBrowserContext', { disposeOnDetach: true })
  contexts.push(browserContextId)
  await call('Browser.grantPermissions', {
    browserContextId, origin: new URL(webUrl).origin, permissions: ['audioCapture', 'videoCapture'],
  })
  const { targetId } = await call('Target.createTarget', { url: 'about:blank', browserContextId })
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true })
  await call('Page.enable', {}, sessionId)
  // Test server uses ephemeral ports, independent of any running wroomd.
  if (signalUrl) {
    await call('Page.addScriptToEvaluateOnNewDocument', {
      source: `window.WebSocket = class extends WebSocket {
        constructor(url, protocols) {
          super(new URL(url, location.href).pathname === '/ws' ? ${JSON.stringify(signalUrl)} : url, protocols)
        }
      }`,
    }, sessionId)
  }
  await call('Page.navigate', { url: webUrl }, sessionId)
  await until('application loaded', () => evaluate(sessionId, 'Boolean(window.__wroomSession)'))
  return sessionId
}
async function join(page, name) {
  await evaluate(page, `window.__wroomSession.join(${JSON.stringify(room)}, ${JSON.stringify(name)})`)
  if (signalUrl) {
    assert.equal(await evaluate(page, 'window.__wroomSession.sig.ws.url'), signalUrl,
      'must connect to the isolated test server, not the deployed server')
  }
}
async function media(page) {
  return evaluate(page, `(async () => {
    const rtc = window.__wroom
    if (!rtc) return null
    const stats = [...(await rtc.subscriber.getStats()).values()]
    const incoming = stats.filter(s => s.type === 'inbound-rtp')
    return {
      connected: rtc.publisher.connectionState === 'connected' && rtc.subscriber.connectionState === 'connected',
      audio: incoming.filter(s => s.kind === 'audio').reduce((n, s) => n + (s.totalSamplesReceived ?? 0), 0),
      video: incoming.filter(s => s.kind === 'video').reduce((n, s) => n + (s.framesDecoded ?? 0), 0),
    }
  })()`)
}
async function waitForMedia(page) {
  await until('two-way connection and decoded media', async () => {
    const state = await media(page)
    return state?.connected && state.audio > 0 && state.video > 0
  })
}
async function arm(page) {
  await evaluate(page, `(() => {
    window.__churnRtc = window.__wroom
    window.__churnDtls = window.__wroom.subscriber.getTransceivers().find(t => t.receiver.transport)?.receiver.transport
    if (!window.__churnDtls) throw new Error('No receiving DTLS transport')
  })()`)
}
async function assertStable(page) {
  const state = await evaluate(page, `({
    sameRtc: window.__wroom === window.__churnRtc,
    dtls: window.__churnDtls.state,
    publisher: window.__wroom.publisher.connectionState,
    subscriber: window.__wroom.subscriber.connectionState,
  })`)
  if (state.dtls !== 'connected' || !state.sameRtc) {
    console.error(await evaluate(page, `(() => {
      const pc = window.__wroom.subscriber
      const summarize = sd => sd?.sdp.split('\\r\\n').filter(l => /^(m=|a=(group:|mid:|inactive|sendonly|recvonly|ice-ufrag:|setup:|candidate:))/.test(l)).join('\\n')
      return {remote: summarize(pc.remoteDescription), local: summarize(pc.localDescription),
        transports: pc.getTransceivers().map(t => ({mid: t.mid, direction: t.currentDirection, state: t.receiver.transport?.state, original: t.receiver.transport === window.__churnDtls}))}
    })()`))
  }
  assert.deepEqual(state, {
    sameRtc: true, dtls: 'connected', publisher: 'connected', subscriber: 'connected',
  }, 'A remote leave/rejoin must not replace or disconnect our transport')
}
async function assertMediaAdvances(pages) {
  const before = await Promise.all(pages.map(media))
  await sleep(1500)
  for (const [i, page] of pages.entries()) {
    const after = await media(page)
    assert.ok(after.audio > before[i].audio, 'received audio samples must advance')
    assert.ok(after.video > before[i].video, 'decoded video frames must advance')
  }
}

// A lost signaling response must not leave a CI process holding test peers.
const watchdog = setTimeout(() => socket.close(), 90_000)
try {
  const a = await newPage()
  const b = await newPage()
  await join(a, 'churn-a')
  await join(b, 'churn-b')
  await Promise.all([a, b].map(waitForMedia))
  await Promise.all([a, b].map(arm))
  await assertMediaAdvances([a, b])
  for (let cycle = 0; cycle < 3; cycle++) {
    const [staying, leaving] = cycle % 2 === 0 ? [a, b] : [b, a]
    await evaluate(leaving, 'window.__wroomSession.leave()')
    // Exercise an empty receive set, not just overlapping publishers.
    await sleep(750)
    await assertStable(staying)
    await join(leaving, `returned-${cycle}`)
    await waitForMedia(leaving)
    await assertStable(staying)
    await arm(leaving)
    await assertMediaAdvances([a, b])
    console.log(`leave/rejoin cycle ${cycle + 1}: same receiving transport, audio/video advancing`)
  }
  // The original cascading failure took ~16 seconds to trigger a rejoin.
  for (let i = 0; i < 40; i++) {
    await sleep(500)
    await Promise.all([a, b].map(assertStable))
  }
  await assertMediaAdvances([a, b])
  console.log('PASS: three alternating rejoins + 20s stable media; no cascading reconnect')
} finally {
  clearTimeout(watchdog)
  for (const browserContextId of contexts) {
    await call('Target.disposeBrowserContext', { browserContextId }).catch(() => {})
  }
  socket.close()
}
