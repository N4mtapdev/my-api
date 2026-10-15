import { Row, Screen, Section, Title } from '@doan-labs/duo-uikit'

// Reminders. A checklist kept in the app's storage, so it survives a reload and both displays agree on it.

import { beep } from '@doan-labs/duo-fixtures'
import { os } from '@doan-labs/duo-sdk'
import { useJSON } from '@doan-labs/duo-sdk/react.ts'
import * as stylex from '@stylexjs/stylex'
import { type KeyboardEvent, useState } from 'react'
import { styles } from './styles.ts'

type Task = { t: string; done: boolean }

const DEFAULTS: Task[] = [
  { t: 'Render lại cảnh macro với 400 mẫu', done: false },
  { t: 'Đo bán kính sống máy với bản mô phỏng', done: false },
  { t: 'Phát hành bản port WebGL studio', done: true },
  { t: 'Hỏi về tone mapping bảng CSS3D', done: false },
  { t: 'Đánh bóng phần titan', done: false }
]

export const Reminders = () => {
  const kv = useJSON<Task[]>(os.storage, 'tasks', DEFAULTS)
  const items = kv.value
  const [draft, setDraft] = useState('')
  const flip = (i: number) => {
    const next = items.map((task, j) => (j === i ? { ...task, done: !task.done } : task))
    kv.set(next)
    if (next[i]!.done) beep([1320, 1760], 0.05, 0.05)
  }
  const add = (e: KeyboardEvent<HTMLInputElement>) => {
    const t = draft.trim()
    if (e.key !== 'Enter' || !t) return
    kv.set([...items, { t, done: false }])
    setDraft('')
  }
  return (
    <Screen>
      <Title xstyle={[styles.blue]}>
        Nhắc việc
        <Title as="span" variant="accessory">
          {items.filter((i) => !i.done).length} cần làm
        </Title>
      </Title>
      <Section xstyle={[styles.white]}>
        {items.map((task, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: tasks are only ever appended, never reordered or removed
          <Row key={i} onClick={() => flip(i)}>
            <span {...stylex.props(styles.chk, task.done && styles.chkOn)} />
            <span {...stylex.props(styles.label, task.done && styles.done)}>{task.t}</span>
          </Row>
        ))}
        <Row>
          <span {...stylex.props(styles.chk, styles.dim)} />
          <input
            {...stylex.props(styles.input)}
            placeholder="Nhắc việc mới"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={add}
          />
        </Row>
      </Section>
    </Screen>
  )
}
