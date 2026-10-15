import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import * as stylex from '@stylexjs/stylex'
import { useState } from 'react'
import type { Place } from './data.ts'
import { styles } from './styles.ts'

/** Apple's place card: a header, the walking time, the details it knows, and the tray. */
export function PlaceCard({ place, onClose }: { place: Place; onClose: () => void }) {
  const [pinned, setPinned] = useState(false)
  const [starred, setStarred] = useState(false)
  return (
    <>
      <div {...stylex.props(styles.cardTop)}>
        <button type="button" aria-label="Đóng" onClick={onClose} {...stylex.props(styles.round, styles.cardClose)}>
          <Sym name="close" size={11} />
        </button>
      </div>
      <div {...stylex.props(styles.scroll)}>
        <h1 {...stylex.props(styles.title)}>{place.name}</h1>
        <div {...stylex.props(styles.kind)}>{place.kind}</div>
        <button type="button" {...stylex.props(styles.go)}>
          <Sym name="walk" size={15} />
          {place.walk} phút
        </button>
        <div {...stylex.props(styles.hdr)}>Chi tiết</div>
        <Field label="Điện thoại" value={place.phone} />
        <Field label="Trang web" value={place.site} />
        <div {...stylex.props(styles.detail)}>
          <span {...stylex.props(styles.label)}>Địa chỉ</span>
          <span {...stylex.props(styles.value)}>
            {place.address.map((line) => (
              <span key={line}>{line}</span>
            ))}
          </span>
        </div>
        <button type="button" aria-pressed={pinned} onClick={() => setPinned(!pinned)} {...stylex.props(styles.action)}>
          <i {...stylex.props(styles.actionGlyph)}>
            <Sym name="pin" size={15} />
          </i>
          {pinned ? 'Đã ghim' : 'Ghim'}
        </button>
        <div {...stylex.props(styles.gap)} />
      </div>
      <div {...stylex.props(styles.tray)}>
        <button
          type="button"
          aria-label="Yêu thích"
          aria-pressed={starred}
          onClick={() => setStarred(!starred)}
          {...stylex.props(styles.ghost, starred && styles.starred)}
        >
          <Sym name="star" size={14} />
        </button>
      </div>
    </>
  )
}

/** A detail Apple knows about the place. What it doesn't know, it leaves out. */
const Field = ({ label, value }: { label: string; value?: string }) =>
  value ? (
    <div {...stylex.props(styles.detail)}>
      <span {...stylex.props(styles.label)}>{label}</span>
      <span {...stylex.props(styles.value)}>{value}</span>
    </div>
  ) : null
