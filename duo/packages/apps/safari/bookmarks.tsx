import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import * as stylex from '@stylexjs/stylex'
import { useState } from 'react'
import { styles } from './styles.ts'

// The cover closes bookmarks from its rail; the inner display passes onClose.
type Props = { onNavigate: (url: string) => void; onClose?: () => void }
type Section = 'bookmarks' | 'reading-list' | 'history'
type Folder = 'recently-saved' | 'favorites' | 'tab-group-favorites'

const sections: [Section, string, 'bookOutline' | 'eye' | 'clockSym'][] = [
  ['bookmarks', 'Dấu trang', 'bookOutline'],
  ['reading-list', 'Danh sách đọc', 'eye'],
  ['history', 'Lịch sử', 'clockSym']
]

const favorites = [
  ['Apple', 'https://www.apple.com', 'apple.com'],
  ['Wikipedia', 'https://en.m.wikipedia.org', 'en.m.wikipedia.org'],
  ['three.js', 'https://threejs.org', 'threejs.org'],
  ['Bun', 'https://bun.sh/docs', 'bun.sh/docs']
] as const

// Recently Saved is the one list Add to Bookmarks writes to; it lives for the session.
export const recent: [string, string, string][] = [
  ['Duo', 'https://duo.doan-labs.com', 'duo.doan-labs.com'],
  ['Wikipedia', 'https://en.m.wikipedia.org', 'en.m.wikipedia.org']
]

const iconFor = (label: string): 'star' | 'globe' | 'bookOutline' =>
  label === 'Apple' ? 'star' : label === 'Wikipedia' ? 'globe' : 'bookOutline'

export const Bookmarks = ({ onNavigate, onClose }: Props) => {
  const [section, setSection] = useState<Section>('bookmarks')
  const [folder, setFolder] = useState<Folder | null>(null)

  const title =
    folder === 'favorites'
      ? 'Yêu thích'
      : folder === 'tab-group-favorites'
        ? 'Yêu thích của nhóm thẻ'
        : 'Đã lưu gần đây'
  const selectSection = (next: Section) => {
    setSection(next)
    setFolder(null)
  }
  const openFolder = (next: Folder) => setFolder(next)
  const showBack = folder !== null
  const showRoot = section === 'bookmarks' && folder === null
  const folderRows = folder === 'favorites' ? favorites : folder === 'recently-saved' ? recent : []

  return (
    <div {...stylex.props(styles.bookmarks)}>
      <div {...stylex.props(styles.bookmarkHeader)}>
        {showBack && (
          <button
            type="button"
            {...stylex.props(styles.bookmarkHeaderBack)}
            aria-label="Quay lại dấu trang"
            onClick={() => setFolder(null)}
          >
            <Sym name="back" size={18} />
          </button>
        )}
        <button
          type="button"
          {...stylex.props(styles.bookmarkHeaderButton)}
          onClick={() => !showBack && openFolder('recently-saved')}
        >
          <span>{title}</span>
          {!showBack && <Sym name="forward" size={15} />}
        </button>
        {onClose && (
          <button type="button" {...stylex.props(styles.bookmarkClose)} aria-label="Đóng dấu trang" onClick={onClose}>
            <Sym name="close" size={13} />
          </button>
        )}
      </div>
      <div {...stylex.props(styles.bookmarkSegments)} role="tablist" aria-label="Các mục dấu trang">
        {sections.map(([id, label, icon]) => (
          <button
            type="button"
            key={id}
            role="tab"
            aria-selected={section === id}
            aria-label={label}
            {...stylex.props(styles.bookmarkSegment, section === id && styles.bookmarkSegmentOn)}
            onClick={() => selectSection(id)}
          >
            <Sym name={icon} size={21} />
          </button>
        ))}
      </div>
      {showRoot ? (
        <>
          <div {...stylex.props(styles.bookmarkSection)}>Thư mục</div>
          <div {...stylex.props(styles.bookmarkGroup)}>
            <button type="button" {...stylex.props(styles.bookmarkRow)} onClick={() => openFolder('favorites')}>
              <span {...stylex.props(styles.bookmarkIcon, styles.bookmarkIconStar)}>
                <Sym name="star" size={17} />
              </span>
              <span>Yêu thích</span>
              <span {...stylex.props(styles.bookmarkCount)}>4</span>
              <Sym name="forward" size={15} />
            </button>
            <button
              type="button"
              {...stylex.props(styles.bookmarkRow)}
              onClick={() => openFolder('tab-group-favorites')}
            >
              <span {...stylex.props(styles.bookmarkIcon, styles.bookmarkIconFolder)}>
                <Sym name="folder" size={17} />
              </span>
              <span>Yêu thích của nhóm thẻ</span>
              <Sym name="forward" size={15} />
            </button>
          </div>
          <div {...stylex.props(styles.bookmarkSection)}>Dấu trang</div>
          <div {...stylex.props(styles.bookmarkGroup)}>
            <button
              type="button"
              {...stylex.props(styles.bookmarkRow)}
              onClick={() => onNavigate('https://support.apple.com/guide/iphone/welcome/ios')}
            >
              <span {...stylex.props(styles.bookmarkIcon, styles.bookmarkIconApple)}></span>
              <span>iPhone User Guide</span>
            </button>
          </div>
        </>
      ) : folder === 'tab-group-favorites' ? (
        <BookmarkList title="Yêu thích của nhóm thẻ" rows={recent} onNavigate={onNavigate} />
      ) : folderRows.length ? (
        <BookmarkList title={title} rows={folderRows} onNavigate={onNavigate} />
      ) : section === 'reading-list' ? (
        <BookmarkList title="Danh sách đọc" rows={recent} onNavigate={onNavigate} />
      ) : (
        <BookmarkList title="Lịch sử" rows={favorites.slice(0, 2)} onNavigate={onNavigate} />
      )}
    </div>
  )
}

const BookmarkList = ({
  title,
  rows,
  onNavigate
}: {
  title: string
  rows: readonly (readonly [string, string, string])[]
  onNavigate: (url: string) => void
}) => (
  <>
    <div {...stylex.props(styles.bookmarkSection)}>{title}</div>
    <div {...stylex.props(styles.bookmarkGroup)}>
      {rows.map(([label, url, detail]) => (
        <button type="button" key={url} {...stylex.props(styles.bookmarkRow)} onClick={() => onNavigate(url)}>
          <span {...stylex.props(styles.bookmarkIcon, styles.bookmarkIconLink)}>
            <Sym name={iconFor(label)} size={17} />
          </span>
          <span {...stylex.props(styles.bookmarkLabel)}>
            <span>{label}</span>
            <span {...stylex.props(styles.bookmarkDetail)}>{detail}</span>
          </span>
          <Sym name="forward" size={15} />
        </button>
      ))}
    </div>
  </>
)
