// Settings › Apps. Every app that was installed rather than baked into the
// shell, with what it is allowed to reach and the button that removes it. The
// rows come from the same `os.store` the App Store drives, so an install or a
// removal shows on both screens and on both displays at once.

import type { Os } from '@doan-labs/duo-sdk'
import type { Store, StoreRow } from '@doan-labs/duo-sdk/store.ts'
import { shared, typography } from '@doan-labs/duo-uikit/styles.ts'
import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import { colors } from '@doan-labs/duo-uikit/tokens.stylex.ts'
import * as stylex from '@stylexjs/stylex'
import { useState, useSyncExternalStore } from 'react'
import { Glyph, Head, Hero, Link, Note, PERM_GLYPH, PERM_LABEL, Row, Section, size, version } from './parts.tsx'
import { styles } from './styles.ts'

const LANE: Record<string, string> = {
  official: 'Danh mục Duo',
  community: 'Cộng đồng',
  development: 'Xem trước tại máy'
}

const useRows = (store: Store) => useSyncExternalStore(store.subscribe, store.snapshot).rows

const Icon = ({ row, big }: { row: StoreRow; big?: boolean }) => {
  const shape = big ? styles.appIconBig : styles.appIcon
  return row.icon ? (
    <img src={row.icon} alt="" {...stylex.props(shape)} />
  ) : (
    <span {...stylex.props(shape, typography.subheadline, styles.appLetter)}>{row.name.slice(0, 1)}</span>
  )
}

export function AppsPage({ os }: { os: Os }) {
  if (!os.store) return <Note>Không dùng được Ứng dụng: máy này không có bộ nhớ để cài vào.</Note>
  return <Installed os={os} store={os.store} />
}

function Installed({ os, store }: { os: Os; store: Store }) {
  const rows = useRows(store).filter((row) => row.installed)
  const busy = rows.filter((row) => row.progress !== undefined)
  return (
    <>
      <Hero name="grid" bg={colors.indigo} title="Ứng dụng">
        Quản lý các app đã cài trên máy Duo này: mỗi app được phép với tới gì, chiếm bao nhiêu dung lượng và có ở lại
        không.
      </Hero>
      {rows.length === 0 ? (
        <Note>Chưa cài gì cả. Mở App Store để lấy một app.</Note>
      ) : (
        <>
          <Head>
            {rows.length} app đã cài · {size(rows.reduce((n, row) => n + (row.bytes ?? 0), 0))}
          </Head>
          <Section>
            {rows.map((row) => (
              <Link
                key={row.id}
                title={row.name}
                icon={<Icon row={row} />}
                label={row.name}
                subtitle={`${row.author} · ${size(row.bytes)}`}
                page={() => <Detail id={row.id} os={os} store={store} />}
              />
            ))}
          </Section>
        </>
      )}
      <Note>
        Chỉ liệt kê các bản phát hành đã cài. Phần còn lại của màn hình chính được nướng sẵn trong shell, không gỡ được.{' '}
        {busy.length > 0 && 'Đang ghi một app vào bộ nhớ; hàng của nó sẽ cập nhật khi xong.'}
      </Note>
    </>
  )
}

/**
 * One app. `id` rather than the row, so the page keeps following the store after
 * a removal starts and can say so instead of showing a stale snapshot.
 */
function Detail({ id, os, store }: { id: string; os: Os; store: Store }) {
  const row = useRows(store).find((r) => r.id === id)
  const [confirming, setConfirming] = useState(false)
  if (!row?.installed) return <Note>App này không còn được cài.</Note>
  const working = row.progress !== undefined
  const remove = () => void store.remove(row.id)
  return (
    <>
      <div {...stylex.props(shared.grp, styles.card, styles.hero)}>
        <Icon row={row} big />
        <div {...stylex.props(typography.title1)}>{row.name}</div>
        <div {...stylex.props(typography.body, styles.heroText)}>{row.author}</div>
      </div>
      <Section>
        <Row label="Phiên bản" detail={version(row.installed)} />
        <Row label="Dung lượng" detail={size(row.bytes)} />
        <Row label="Nguồn" detail={LANE[row.lane] ?? row.lane} />
      </Section>
      <Head>Truy cập thiết bị</Head>
      <Section>
        {row.permissions.length ? (
          row.permissions.map((name) => (
            <Row
              key={name}
              icon={<Glyph name={PERM_GLYPH[name] ?? 'lock'} bg={colors.blue} />}
              label={PERM_LABEL[name] ?? name}
            />
          ))
        ) : (
          <Row icon={<Glyph name="lock" bg={colors.grey} />} label="Không truy cập thiết bị" />
        )}
      </Section>
      <Note>
        {row.development
          ? 'Bản xem trước tại máy. Gỡ đi sẽ xóa dữ liệu riêng của bản xem trước này.'
          : 'Chạy trong sandbox riêng: không máy ảnh, không micrô, không trang nhúng. Bộ nhớ của nó không bao giờ rời máy này.'}
      </Note>
      <Section>
        <button
          type="button"
          {...stylex.props(shared.row, styles.row, styles.action)}
          onClick={() => os.open(row.name)}
          disabled={working}
        >
          Mở {row.name}
        </button>
        {row.recovery && (
          <button
            type="button"
            {...stylex.props(shared.row, styles.row, styles.action, working && styles.busy)}
            onClick={() => void store.restore(row.id)}
            disabled={working}
          >
            <Sym name="undo" size={15} />
            Khôi phục phiên bản trước
          </button>
        )}
      </Section>
      {/* A preinstalled app reinstalls itself at the next start, so nothing offers to remove it. */}
      {row.preinstalled ? null : confirming ? (
        <>
          <Section>
            <button
              type="button"
              {...stylex.props(shared.row, styles.row, styles.destructive, working && styles.busy)}
              onClick={remove}
              disabled={working}
            >
              Xóa “{row.name}”
            </button>
            <button
              type="button"
              {...stylex.props(shared.row, styles.row, styles.action, styles.centred)}
              onClick={() => setConfirming(false)}
            >
              Hủy
            </button>
          </Section>
          <Note>Xóa app cũng xóa luôn dữ liệu của nó. Cài lại sẽ khởi động trắng.</Note>
        </>
      ) : (
        <Section>
          <button
            type="button"
            {...stylex.props(shared.row, styles.row, styles.destructive, working && styles.busy)}
            onClick={() => setConfirming(true)}
            disabled={working}
          >
            <Sym name="trash" size={15} />
            Gỡ ứng dụng
          </button>
        </Section>
      )}
      {row.error && <Note>{row.error}</Note>}
    </>
  )
}
