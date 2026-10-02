export type Connection = { endpoint: string; model: string; key: string }
export type ChatMessage = { role: 'system' | 'user' | 'assistant'; content: string }
export type Provider = { id: string; name: string; endpoint: string; model: string; keys: string }
/** OpenAI-compatible endpoints known to allow browser requests. Anything else is a custom endpoint. */
export const PROVIDERS: Provider[] = [
  {
    id: 'openrouter',
    name: 'OpenRouter',
    endpoint: 'https://openrouter.ai/api/v1',
    model: 'openrouter/auto',
    keys: 'https://openrouter.ai/keys'
  },
  {
    id: 'openai',
    name: 'OpenAI',
    endpoint: 'https://api.openai.com/v1',
    model: 'gpt-5',
    keys: 'https://platform.openai.com/api-keys'
  },
  {
    id: 'google',
    name: 'Google Gemini',
    endpoint: 'https://generativelanguage.googleapis.com/v1beta/openai',
    model: 'gemini-2.5-pro',
    keys: 'https://aistudio.google.com/apikey'
  },
  {
    id: 'groq',
    name: 'Groq',
    endpoint: 'https://api.groq.com/openai/v1',
    model: 'openai/gpt-oss-120b',
    keys: 'https://console.groq.com/keys'
  }
]
/** Model IDs the endpoint lists; OpenRouter answers without a key, the others need one. */
export async function models(connection: Connection, signal: AbortSignal): Promise<string[]> {
  const url = endpointURL(connection.endpoint).replace(/chat\/completions$/, 'models')
  const key = connection.key.trim()
  const response = await fetch(url, {
    headers: key ? { Authorization: `Bearer ${key}` } : {},
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal
  })
  if (!response.ok) throw new Error(`Model list unavailable (${response.status})`)
  const data = await response.json()
  const list: unknown[] = Array.isArray(data?.data) ? data.data : []
  return list
    .map((m) =>
      m && typeof m === 'object' && typeof (m as { id?: unknown }).id === 'string' ? (m as { id: string }).id : ''
    )
    .filter(Boolean)
    .map((id) => id.replace(/^models\//, ''))
    .sort()
}
export function endpointURL(base: string) {
  const url = new URL(base.trim())
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
    throw new Error('Dùng URL API HTTPS, không kèm thông tin đăng nhập, tham số truy vấn hay fragment')
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/chat/completions`
  return url.href
}
export async function completion(
  connection: Connection,
  messages: ChatMessage[],
  signal: AbortSignal,
  progress: (characters: number) => void = () => {},
  test = false
) {
  const url = endpointURL(connection.endpoint)
  if (!connection.key.trim()) throw new Error('Nhập API key trong phần Kết nối')
  if (!connection.model.trim()) throw new Error('Nhập ID model trong phần Kết nối')
  const timeout = AbortSignal.timeout(180_000)
  const combined = AbortSignal.any([signal, timeout])
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: { Authorization: `Bearer ${connection.key.trim()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: connection.model.trim(), messages, stream: true, max_tokens: test ? 16 : 12000 }),
      signal: combined
    })
  } catch {
    if (combined.aborted) throw new Error(signal.aborted ? 'Đã dừng' : 'Provider phản hồi quá lâu (3 phút)')
    throw new Error('Không kết nối được endpoint này. Kiểm tra URL, kết nối và việc provider có hỗ trợ CORS từ trình duyệt không.')
  }
  if (!response.ok) {
    void response.body?.cancel()
    const reason: Record<number, string> = {
      401: 'API key bị từ chối',
      403: 'Provider từ chối truy cập',
      402: 'Provider đã hết credit',
      429: 'Provider bị giới hạn tần suất; thử lại sau'
    }
    throw new Error(reason[response.status] ?? `Yêu cầu tới provider thất bại (${response.status})`)
  }
  if (!response.body) throw new Error('Provider trả về phản hồi rỗng')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const streaming = response.headers.get('content-type')?.includes('text/event-stream')
  let buffer = '',
    output = '',
    received = 0,
    complete = false
  function consume(json: string) {
    if (json === '[DONE]') {
      complete = true
      return
    }
    const data = JSON.parse(json)
    if (data.error) throw new Error('Provider báo lỗi khi tạo nội dung')
    const choice = data.choices?.[0]
    if (choice?.finish_reason === 'length') throw new Error('Phản hồi bị cắt ngắn. Hãy yêu cầu một app nhỏ hơn.')
    if (choice?.finish_reason === 'content_filter') throw new Error('Provider từ chối yêu cầu này')
    const content = choice?.delta?.content ?? choice?.message?.content
    if (typeof content === 'string') {
      output += content
      progress(output.length)
    }
    if (choice?.finish_reason === 'stop') complete = true
  }
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      received += value.byteLength
      if (received > 2_000_000) throw new Error('Phản hồi của provider vượt giới hạn kích thước')
      buffer += decoder.decode(value, { stream: true }).replace(/\r/g, '')
      if (streaming) {
        let index = buffer.indexOf('\n\n')
        while (index !== -1) {
          const event = buffer.slice(0, index)
          buffer = buffer.slice(index + 2)
          const data = event
            .split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => line.slice(5).trimStart())
            .join('\n')
          if (data) consume(data)
          index = buffer.indexOf('\n\n')
        }
      }
    }
    buffer += decoder.decode()
    if (!streaming) consume(buffer)
    if (!complete || !output.trim()) throw new Error('Luồng phản hồi của provider kết thúc khi chưa có phản hồi hoàn chỉnh')
    return output
  } finally {
    await reader.cancel().catch(() => {})
  }
}
