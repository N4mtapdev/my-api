// Settings › General, and the panes under it: About, Software Update, Duo
// Storage and the reset. Nothing here is a placeholder: the numbers come from
// the store and from `navigator.storage.estimate()`, and Erase All Content and
// Settings really does empty the device and reboot it.

import type { Os, SettingsHost } from '@doan-labs/duo-sdk'
import { HOST_SDK } from '@doan-labs/duo-sdk/compat.ts'
import type { Store } from '@doan-labs/duo-sdk/store.ts'
import { shared, typography } from '@doan-labs/duo-uikit/styles.ts'
import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import { colors } from '@doan-labs/duo-uikit/tokens.stylex.ts'
import * as stylex from '@stylexjs/stylex'
import { useEffect, useState, useSyncExternalStore } from 'react'
import { emptyStore, Glyph, Head, Hero, Link, Note, noStore, Row, Section, size } from './parts.tsx'
import { styles } from './styles.ts'

export const SOFTWARE = 'iOS 27.0'
const MODEL = 'N4mtapdev'
const STUDIO = 'https://n4mtapdev.com'
const SOURCE = 'https://github.com/N4mtapdev/iphoneduo'
/** One colour per app in the storage bar, reused round the list. */
const SEGMENTS = [colors.blue, colors.green, colors.orange, colors.purple, colors.teal, colors.pink]

export function GeneralPage({ os, host }: { os: Os; host: SettingsHost }) {
  return (
    <>
      <Hero name="gear" bg={colors.grey} title="Cài đặt chung">
        Quản lý thiết lập và tuỳ chọn chung của máy Duo này: đang chạy gì, còn bao nhiêu dung lượng, và cần gì để đưa
        máy về như lúc xuất xưởng.
      </Hero>
      <Section>
        <Link
          title="Giới thiệu"
          icon={<Glyph name="iphone" bg={colors.grey} />}
          label="Giới thiệu"
          page={() => <AboutPage os={os} host={host} />}
        />
        <Link
          title="Cập nhật phần mềm"
          icon={<Glyph name="gear" bg={colors.grey} />}
          label="Cập nhật phần mềm"
          page={() => <UpdatePage />}
        />
        <Link
          title="Bộ nhớ Duo"
          icon={<Glyph name="folder" bg={colors.grey} />}
          label="Bộ nhớ Duo"
          page={() => <StoragePage store={os.store} />}
        />
      </Section>
      <Section>
        <Link
          title="Chuyển hoặc Đặt lại iPhone"
          icon={<Glyph name="undo" bg={colors.grey} />}
          label="Chuyển hoặc Đặt lại iPhone"
          page={() => <ResetPage host={host} />}
        />
      </Section>
      <Note>
        Chuyển hoặc Đặt lại giữ hành động phá hủy duy nhất trên máy. Mọi thứ nó dọn nằm trong trình duyệt này; không có
        gì được gửi đi đâu cả.
      </Note>
    </>
  )
}

function AboutPage({ os, host }: { os: Os; host: SettingsHost }) {
  const rows = useSyncExternalStore(
    os.store?.subscribe ?? noStore,
    os.store?.snapshot ?? emptyStore,
    os.store?.snapshot ?? emptyStore
  ).rows
  const installed = rows.filter((row) => row.installed)
  const estimate = useEstimate()
  return (
    <>
      <Section>
        <Row label="Tên" detail={MODEL} />
        <Row label="Phiên bản phần mềm" detail={SOFTWARE} />
        <Row label="Kiểu máy" detail={MODEL} />
        <Row label="SDK nền tảng" detail={HOST_SDK} />
      </Section>
      <Section>
        <Row label="Ứng dụng" detail={String(installed.length)} />
        <Row label="Đã dùng" detail={estimate ? size(estimate.usage) : 'Đang đo…'} />
        <Row label="Khả dụng" detail={estimate ? size(estimate.free) : 'Đang đo…'} />
      </Section>
      <Note>
        Dung lượng là mức trình duyệt sẵn sàng cấp cho origin này, không phải một đĩa cố định. Nó dịch chuyển khi trình
        duyệt tính lại hạn ngạch.
      </Note>
      <Head>Sản phẩm của</Head>
      <Section>
        <button
          type="button"
          {...stylex.props(shared.row, styles.row, styles.action)}
          onClick={() => host.openExternal(STUDIO)}
        >
          <Sym name="globe" size={15} />
          N4mtapdev
        </button>
        <button
          type="button"
          {...stylex.props(shared.row, styles.row, styles.action)}
          onClick={() => host.openExternal(SOURCE)}
        >
          <Sym name="document" size={15} />
          Mã nguồn trên GitHub
        </button>
      </Section>
      <Note>
        Một bản dựng thử nghiệm về chiếc iPhone gập của Apple, làm từ mô hình đã công bố và quay thực tế. Không phải sản
        phẩm của Apple và không liên kết với Apple.
      </Note>
    </>
  )
}

function UpdatePage() {
  return (
    <>
      <Hero name="gear" bg={colors.grey} title={SOFTWARE}>
        {MODEL} đã là bản mới nhất.
      </Hero>
      <Note>
        Máy có shell đúng như lúc dựng; không có máy chủ cập nhật phía sau. Bản mới đến bằng cách tải lại trang. App đã
        cài thì cập nhật qua App Store.
      </Note>
    </>
  )
}

function StoragePage({ store }: { store?: Store }) {
  const rows = useSyncExternalStore(
    store?.subscribe ?? noStore,
    store?.snapshot ?? emptyStore,
    store?.snapshot ?? emptyStore
  )
    .rows.filter((row) => row.installed && row.bytes)
    .sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0))
  const estimate = useEstimate()
  const apps = rows.reduce((n, row) => n + (row.bytes ?? 0), 0)
  // The bar divides what is used, not the quota: a browser hands out gigabytes
  // and a release is tens of kilobytes, so against the quota every app is one
  // invisible sliver. Against the usage the split is the information.
  const used = Math.max(estimate?.usage ?? 0, apps)
  const other = used - apps
  return (
    <>
      <div {...stylex.props(shared.grp, styles.card, styles.measure)}>
        <div {...stylex.props(typography.title1)}>{estimate ? size(estimate.usage) : '—'}</div>
        <div {...stylex.props(typography.body, styles.heroText)}>
          đã dùng, trên tổng {estimate ? size(estimate.quota) : '—'} mà trình duyệt cho phép
        </div>
        <div {...stylex.props(styles.bar)}>
          {used > 0 && (
            <>
              {rows.map((row, i) => (
                <span
                  key={row.id}
                  {...stylex.props(styles.seg(SEGMENTS[i % SEGMENTS.length]!, ((row.bytes ?? 0) / used) * 100))}
                />
              ))}
              <span {...stylex.props(styles.seg(colors.grey3, (other / used) * 100))} />
            </>
          )}
        </div>
        <div {...stylex.props(typography.caption1, styles.legend)}>
          {rows.map((row, i) => (
            <span key={row.id} {...stylex.props(styles.key)}>
              <span {...stylex.props(styles.dot, styles.tint(SEGMENTS[i % SEGMENTS.length]!))} />
              {row.name}
            </span>
          ))}
          <span {...stylex.props(styles.key)}>
            <span {...stylex.props(styles.dot, styles.tint(colors.grey3))} />
            Shell and app data · {size(other)}
          </span>
        </div>
      </div>
      <Head>App đã cài · {size(apps)}</Head>
      <Section>
        {rows.length ? (
          rows.map((row) => <Row key={row.id} label={row.name} subtitle={row.author} detail={size(row.bytes)} />)
        ) : (
          <Row label="Chưa cài app nào" />
        )}
      </Section>
      <Note>
        Kích thước app là số byte của bản phát hành máy đã tải về. Phần còn lại của tổng số đo được là cache của shell
        và dữ liệu mỗi app đã ghi kể từ đó.
      </Note>
    </>
  )
}

function ResetPage({ host }: { host: SettingsHost }) {
  const [confirming, setConfirming] = useState(false)
  const [erasing, setErasing] = useState(false)
  const [error, setError] = useState('')
  return (
    <>
      <Section>
        <button
          type="button"
          {...stylex.props(shared.row, styles.row, styles.destructive, erasing && styles.busy)}
          onClick={() => setConfirming(true)}
          disabled={erasing || confirming}
        >
          <Sym name="trash" size={15} />
          Xóa mọi nội dung và cài đặt
        </button>
      </Section>
      <Note>
        Thao tác này gỡ mọi app đã cài cùng dữ liệu, màn hình chính bạn đã sắp, hình nền bạn đã chọn và các ghi chú, địa
        điểm, cài đặt mỗi app đã lưu. Máy khởi động lại và cài lại các app có sẵn, đúng như lần truy cập đầu tiên.
      </Note>
      {confirming && (
        <>
          <Section>
            <button
              type="button"
              {...stylex.props(shared.row, styles.row, styles.destructive, erasing && styles.busy)}
              disabled={erasing}
              onClick={() => {
                setErasing(true)
                setError('')
                host.erase().catch((reason: unknown) => {
                  setErasing(false)
                  setError(String(reason))
                })
              }}
            >
              {erasing ? 'Đang xóa…' : `Xóa ${MODEL}`}
            </button>
            <button
              type="button"
              {...stylex.props(shared.row, styles.row, styles.action, styles.centred)}
              disabled={erasing}
              onClick={() => setConfirming(false)}
            >
              Hủy
            </button>
          </Section>
          <Note>Không thể hoàn tác. Trang sẽ tải lại ngay khi máy trống rỗng.</Note>
        </>
      )}
      {error && <Note>Xóa thất bại: {error}</Note>}
    </>
  )
}

/** `navigator.storage.estimate()`, measured once per mount. Undefined until it answers. */
function useEstimate() {
  const [value, setValue] = useState<{ usage: number; quota: number; free: number }>()
  useEffect(() => {
    let live = true
    navigator.storage
      ?.estimate?.()
      .then(({ usage = 0, quota = 0 }) => {
        if (live) setValue({ usage, quota, free: Math.max(0, quota - usage) })
      })
      .catch(() => {})
    return () => {
      live = false
    }
  }, [])
  return value
}
