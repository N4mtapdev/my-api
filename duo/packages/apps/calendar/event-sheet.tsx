import { Button, HStack, Select, Sheet, Text, TextField, Toggle, VStack } from '@doan-labs/duo-uikit'
import * as stylex from '@stylexjs/stylex'
import { useEffect, useState } from 'react'
import type { Cal, Event } from './data.ts'
import { styles } from './styles.ts'

type Props = {
  draft: Event | null
  isNew: boolean
  calendars: Cal[]
  onSave: (e: Event) => void
  onDelete: (id: string) => void
  onClose: () => void
}

/** New and existing events share the form; `isNew` only changes the buttons. */
export function EventSheet({ draft, isNew, calendars, onSave, onDelete, onClose }: Props) {
  const [e, setE] = useState<Event | null>(draft)
  useEffect(() => setE(draft), [draft])
  const put = (patch: Partial<Event>) => setE((x) => x && { ...x, ...patch })
  const setAllDay = (allDay: boolean) =>
    e &&
    put({
      allDay,
      start: `${e.start.slice(0, 10)}T${allDay ? '00:00' : '09:00'}`,
      end: `${e.end.slice(0, 10)}T${allDay ? '00:00' : '10:00'}`
    })
  const setStart = (start: string) => e && put({ start, end: start > e.end ? start : e.end })
  const dateOnly = e?.allDay
  // Not a <form>: the app frame is sandboxed without allow-forms, so a submit event never fires.
  const submit = () => e && e.end >= e.start && onSave(e)
  return (
    <Sheet open={!!draft} onClose={onClose}>
      {e && (
        <div {...stylex.props(styles.form)}>
          <TextField
            aria-label="Tiêu đề"
            placeholder="Sự kiện mới"
            value={e.title}
            onChange={(ev) => put({ title: ev.target.value })}
            autoFocus
            onKeyDown={(ev) => ev.key === 'Enter' && submit()}
            xstyle={[styles.titleField]}
          />
          <TextField
            aria-label="Địa điểm"
            placeholder="Thêm địa điểm"
            value={e.location ?? ''}
            onChange={(ev) => put({ location: ev.target.value })}
          />
          <HStack justify="between" as="label">
            <Text size="callout">cả ngày</Text>
            <Toggle checked={!!e.allDay} onChange={(ev) => setAllDay(ev.target.checked)} />
          </HStack>
          <HStack gap={8} as="label">
            <Text size="callout" xstyle={[styles.fieldLabel]}>
              bắt đầu
            </Text>
            <TextField
              type={dateOnly ? 'date' : 'datetime-local'}
              value={dateOnly ? e.start.slice(0, 10) : e.start}
              onChange={(ev) => setStart(dateOnly ? `${ev.target.value}T00:00` : ev.target.value)}
              required
              xstyle={[styles.grow]}
            />
          </HStack>
          <HStack gap={8} as="label">
            <Text size="callout" xstyle={[styles.fieldLabel]}>
              kết thúc
            </Text>
            <TextField
              type={dateOnly ? 'date' : 'datetime-local'}
              value={dateOnly ? e.end.slice(0, 10) : e.end}
              min={dateOnly ? e.start.slice(0, 10) : e.start}
              onChange={(ev) => put({ end: dateOnly ? `${ev.target.value}T00:00` : ev.target.value })}
              required
              xstyle={[styles.grow]}
            />
          </HStack>
          <HStack gap={8} as="label">
            <Text size="callout" xstyle={[styles.fieldLabel]}>
              lịch
            </Text>
            <Select value={e.calendar} onChange={(ev) => put({ calendar: ev.target.value })} xstyle={[styles.grow]}>
              {calendars.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </Select>
          </HStack>
          <TextField
            multiline
            aria-label="Ghi chú"
            placeholder="Thêm ghi chú"
            value={e.notes ?? ''}
            onChange={(ev) => put({ notes: ev.target.value })}
          />
          <HStack gap={8} justify="end">
            {!isNew && (
              <Button variant="plain" onClick={() => onDelete(e.id)} xstyle={[styles.red]}>
                Xóa
              </Button>
            )}
            <VStack xstyle={[styles.grow]} />
            <Button onClick={onClose}>Hủy</Button>
            <Button variant="filled" onClick={submit}>
              {isNew ? 'Thêm' : 'Xong'}
            </Button>
          </HStack>
        </div>
      )}
    </Sheet>
  )
}
