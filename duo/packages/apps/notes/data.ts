export type Note = {
  id: string
  /** Creation time, ISO. The body lives in storage under `note:<id>`. */
  when: string
  /** Folder id; unset means the built-in "Notes" folder. */
  folder?: string
}

export type Folder = { id: string; name: string }

/** The line under the toolbar in the real editor: "September 18, 2026 at 3:38 PM". */
export const longStamp = (note: Note) => {
  const d = new Date(note.when)
  return `${d.toLocaleDateString('vi-VN', { day: 'numeric', month: 'long', year: 'numeric' })} lúc ${d.toLocaleTimeString('vi-VN', { hour: 'numeric', minute: '2-digit' })}`
}

const sameDay = (a: Date, b: Date) => a.toDateString() === b.toDateString()

/** Today's notes show a time, older ones a date, like the real list. */
export const stamp = (note: Note) => {
  const d = new Date(note.when)
  return sameDay(d, new Date())
    ? d.toLocaleTimeString('vi-VN', { hour: 'numeric', minute: '2-digit' })
    : d.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: '2-digit' })
}

/** Section header a note files under: Today, Yesterday, then the month. */
export const groupOf = (note: Note) => {
  const d = new Date(note.when)
  const now = new Date()
  if (sameDay(d, now)) return 'Hôm nay'
  if (sameDay(d, new Date(now.getTime() - 864e5))) return 'Hôm qua'
  return d.toLocaleDateString('vi-VN', {
    month: 'long',
    year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric'
  })
}

export const group = (notes: Note[]) =>
  [...new Set(notes.map(groupOf))].map((name) => ({ name, notes: notes.filter((n) => groupOf(n) === name) }))
