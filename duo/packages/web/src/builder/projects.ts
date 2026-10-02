import { example } from './example'
import type { Project } from './types'

export function newProject(): Project {
  return {
    id: crypto.randomUUID(),
    name: 'App chưa đặt tên',
    messages: [],
    current: 0,
    revisions: [{ id: crypto.randomUUID(), at: Date.now(), source: example }]
  }
}
function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('duo-builder', 1)
    request.onupgradeneeded = () => request.result.createObjectStore('projects', { keyPath: 'id' })
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error('Bộ nhớ cục bộ không khả dụng. Tải mã nguồn về trước khi rời trang.'))
  })
}
export async function listProjects(): Promise<Project[]> {
  const db = await database()
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction('projects').objectStore('projects').getAll()
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(new Error('Không đọc được dự án trên máy'))
    })
  } finally {
    db.close()
  }
}
export async function saveProject(project: Project) {
  const db = await database()
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('projects', 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = tx.onabort = () => reject(new Error('Không lưu được trên máy. Tải mã nguồn về trước khi rời trang.'))
      tx.objectStore('projects').put(project)
    })
  } finally {
    db.close()
  }
}
export function downloadProject(project: Project) {
  const content = {
    format: 'duo-builder-source-v1',
    project,
    instructions: 'Source export only. No API key or published release is included.'
  }
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${project.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'duo-app'}.json`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
