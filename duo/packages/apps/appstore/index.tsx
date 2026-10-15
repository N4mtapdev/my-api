// App Store. The real catalog laid out like the App Store: a Today card for the
// featured release, then a carousel per lane whose columns of three rows page
// sideways, a detail page per app and the developer tools at the bottom. Every
// row and button here is what the store checks drive.

import { art } from '@doan-labs/duo-fixtures'
import type { Os } from '@doan-labs/duo-sdk'
import { PREVIEW_FEATURES } from '@doan-labs/duo-sdk/preview-features.ts'
import type { Store, StoreRow } from '@doan-labs/duo-sdk/store.ts'
import { LargeTitle, Placeholder, Screen, Section, useWide, VStack } from '@doan-labs/duo-uikit'
import { Nav, Page, useNav } from '@doan-labs/duo-uikit/nav.tsx'
import { animations, shared } from '@doan-labs/duo-uikit/styles.ts'
import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import * as stylex from '@stylexjs/stylex'
import { type ReactNode, useState, useSyncExternalStore } from 'react'
import { styles } from './styles.ts'

/** Where app authors go to publish; opened outside the device, so the shell hands us the opener. */
const SUBMIT_URL = 'https://duo.doan-labs.com/publish'
type Open = Os['open']
type External = (url: string) => void

/** Permission labels come from the runtime; the glyph is ours. */
const PERM_GLYPH: Record<string, Parameters<typeof Sym>[0]['name']> = {
  Location: 'location',
  Photos: 'grid',
  'Read clipboard': 'note',
  'Write clipboard': 'compose'
}
/** The runtime's permission names, shown to the reader in Vietnamese. */
const PERM_LABEL: Record<string, string> = {
  Location: 'Vị trí',
  Photos: 'Ảnh',
  'Read clipboard': 'Đọc bộ nhớ tạm',
  'Write clipboard': 'Ghi bộ nhớ tạm'
}
const size = (bytes?: number) =>
  bytes === undefined
    ? '—'
    : bytes < 1e6
      ? `${Math.max(1, Math.round(bytes / 1e3))} KB`
      : `${(bytes / 1e6).toFixed(1)} MB`
const version = (row: StoreRow) => (row.installed ?? row.version)?.split('+')[0] ?? 'Không có'
const hasUpdate = (row: StoreRow) =>
  PREVIEW_FEATURES.stageUpdates && !!row.installed && !row.development && !!row.version && row.version !== row.installed
const needsRetry = (row: StoreRow) =>
  !!row.failed && (!row.version || row.version === row.failed || row.version === row.installed)

export function AppStore({ os, openExternal }: { os: Os; openExternal: External }) {
  return os.store ? (
    <Nav>
      <Shelf store={os.store} open={os.open} openExternal={openExternal} />
    </Nav>
  ) : (
    <Placeholder>Không dùng được cửa hàng</Placeholder>
  )
}

/** What a row says under its name: who made it, and what it reaches for. */
const tagline = (row: StoreRow) =>
  row.permissions.length
    ? `Dùng ${row.permissions
        .map((p) => PERM_LABEL[p] ?? p)
        .join(', ')
        .toLowerCase()}`
    : 'Trong sandbox, không truy cập thiết bị'

function Shelf({ store, open, openExternal }: { store: Store; open: Open; openExternal: External }) {
  const state = useSyncExternalStore(store.subscribe, store.snapshot)
  const { push } = useNav()
  // Wide gets two carousel pages side by side and a hero with room for its icon.
  const [head, wide] = useWide()
  const [tab, setTab] = useState('Ứng dụng')
  const [lane, setLane] = useState('all')
  const [query, setQuery] = useState('')
  const q = query.trim().toLowerCase()
  const rows = state.rows.filter(
    (row) =>
      (row.name.toLowerCase().includes(q) || row.author.toLowerCase().includes(q)) &&
      (tab !== 'Cập nhật' || (row.installed && (row.version !== row.installed || row.failed || row.candidate)))
  )
  const official = rows.filter((r) => r.lane === 'official')
  const community = rows.filter((r) => r.lane === 'community')
  const development = rows.filter((r) => r.lane === 'development')
  // One featured app a day, rotating through the compatible official releases.
  const day = Math.floor(Date.now() / 864e5)
  const pool = state.rows.filter((r) => r.lane === 'official' && r.compatible)
  const featured =
    !q && tab === 'Ứng dụng' && (lane === 'all' || lane === 'official') && pool.length
      ? pool[day % pool.length]
      : undefined
  const lanes = [
    { key: 'all', label: 'Tất cả', n: rows.length },
    { key: 'official', label: 'Chính thức', n: official.length },
    { key: 'community', label: 'Cộng đồng', n: community.length },
    ...(development.length ? [{ key: 'development', label: 'Xem trước tại máy', n: development.length }] : [])
  ]
  const show = (row: StoreRow) =>
    push((back) => <Detail id={row.id} store={store} open={open} openExternal={openExternal} back={back} />)
  const tabs = PREVIEW_FEATURES.stageUpdates ? ['Ứng dụng', 'Cập nhật'] : ['Ứng dụng']
  const group = (key: string, title: string, blurb: string, list: StoreRow[]) =>
    (lane === 'all' || lane === key) && (
      <Group title={title} blurb={blurb} rows={list} wide={wide} store={store} open={open} onShow={show} />
    )
  return (
    <VStack>
      <div ref={head} {...stylex.props(styles.top)}>
        <LargeTitle as="h1" xstyle={styles.title}>
          App Store
        </LargeTitle>
        <label {...stylex.props(styles.search)}>
          <Sym name="search" size={15} />
          <input
            aria-label="Tìm ứng dụng"
            placeholder="Ứng dụng, trò chơi và hơn thế nữa"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            {...stylex.props(styles.searchInput)}
          />
        </label>
        <button
          type="button"
          aria-label="Làm mới danh mục"
          title={state.source}
          {...stylex.props(styles.iconBtn, state.developer && styles.iconBtnDev, shared.press)}
          onClick={() => {
            void store.refresh()
          }}
        >
          <Sym name="reload" size={15} />
        </button>
      </div>
      <Screen>
        <div {...stylex.props(styles.filters)}>
          {tabs.length > 1 && (
            <nav aria-label="Các mục của cửa hàng" {...stylex.props(styles.seg)}>
              {tabs.map((name) => (
                <button
                  key={name}
                  type="button"
                  aria-pressed={name === tab}
                  onClick={() => setTab(name)}
                  {...stylex.props(styles.segBtn, name === tab && styles.segOn)}
                >
                  {name}
                </button>
              ))}
            </nav>
          )}
          <nav aria-label="Nhóm" {...stylex.props(styles.chips)}>
            {lanes.map((l) => (
              <button
                key={l.key}
                type="button"
                aria-pressed={lane === l.key}
                onClick={() => setLane(l.key)}
                {...stylex.props(styles.chip, lane === l.key && styles.chipOn, shared.press)}
              >
                {l.label}
                <span {...stylex.props(styles.chipN)}>{l.n}</span>
              </button>
            ))}
          </nav>
        </div>
        {state.error && (
          <div role="status" {...stylex.props(styles.banner)}>
            <Sym name="antenna" size={14} />
            Danh mục đang offline. Đang hiện các bản phát hành có sẵn gần nhất.
          </div>
        )}
        {state.developer && (
          <div role="status" {...stylex.props(styles.banner, styles.bannerDev)}>
            <Sym name="tabs" size={14} />
            Danh mục nhà phát triển: {new URL(state.source).host}
          </div>
        )}
        {state.loading && !state.rows.length ? (
          <div role="status" {...stylex.props(styles.center)}>
            <i {...stylex.props(styles.spinner, animations.spin)} />
            Đang tải danh mục…
          </div>
        ) : (
          <>
            {featured && (
              <Featured row={featured} wide={wide} store={store} open={open} onShow={() => show(featured)} />
            )}
            {group('official', 'Từ Doan Labs', 'Bản phát hành chính thức, dựng cho cả hai màn hình.', official)}
            {group('community', 'Cộng đồng', 'Gửi bằng pull request, được rà soát rồi phát hành.', community)}
            {group('development', 'Xem trước tại máy', 'Từ danh mục nhà phát triển của bạn.', development)}
            {!rows.length && (
              <Placeholder xstyle={[styles.center]}>
                Không có {tab === 'Cập nhật' ? 'bản cập nhật' : 'app'} nào.
              </Placeholder>
            )}
          </>
        )}
        <Developer store={store} openExternal={openExternal} source={state.source} developer={state.developer} />
      </Screen>
    </VStack>
  )
}

/** The Today card: the app's own icon, blurred, is the artwork; the icon itself floats over it. */
function Featured({
  row,
  wide,
  store,
  open,
  onShow
}: {
  row: StoreRow
  wide: boolean
  store: Store
  open: Open
  onShow: () => void
}) {
  return (
    <div {...stylex.props(styles.hero, styles.heroArt(art(row.name, 46)), shared.select)}>
      {row.icon && <img src={row.icon} alt="" aria-hidden="true" {...stylex.props(styles.heroBlur)} />}
      <div {...stylex.props(styles.heroShade)} />
      <button type="button" onClick={onShow} {...stylex.props(styles.bare, styles.heroTop, wide && styles.heroTopWide)}>
        <div {...stylex.props(styles.heroText)}>
          <div {...stylex.props(styles.kicker)}>{row.installed ? 'Trên máy Duo của bạn' : 'Nổi bật hôm nay'}</div>
          <div {...stylex.props(styles.heroName)}>{row.name}</div>
          <div {...stylex.props(styles.heroBlurb)}>
            {tagline(row)}. Mã nguồn mở, giấy phép MIT{row.note ? `. ${row.note}` : '.'}
          </div>
        </div>
        {wide && <Icon row={row} xstyle={styles.heroBig} />}
      </button>
      <div {...stylex.props(styles.heroBar)}>
        <Icon row={row} xstyle={styles.heroIcon} />
        <div {...stylex.props(styles.heroInfo)}>
          <div {...stylex.props(styles.heroTitle)}>{row.name}</div>
          <div {...stylex.props(styles.heroSub)}>
            {row.author} · {size(row.bytes)}
          </div>
        </div>
        <Action row={row} store={store} open={open} light />
      </div>
    </div>
  )
}

/** A lane: heading, then its rows, two columns across in a wide box. */
function Group({
  title,
  blurb,
  rows,
  wide,
  store,
  open,
  onShow
}: {
  title: string
  blurb: string
  rows: StoreRow[]
  wide: boolean
  store: Store
  open: Open
  onShow: (row: StoreRow) => void
}) {
  if (!rows.length) return null
  return (
    <section aria-label={title} {...stylex.props(styles.group)}>
      <div {...stylex.props(styles.h)}>
        <div>
          <div {...stylex.props(styles.hTitle)}>{title}</div>
          <div {...stylex.props(styles.hBlurb)}>{blurb}</div>
        </div>
        <span {...stylex.props(styles.hCount)}>{rows.length} app</span>
      </div>
      <div {...stylex.props(styles.grid, wide && styles.gridWide)}>
        {rows.map((row) => (
          <Item key={row.id} row={row} store={store} open={open} onShow={() => onShow(row)} />
        ))}
      </div>
    </section>
  )
}

function Item({ row, store, open, onShow }: { row: StoreRow; store: Store; open: Open; onShow: () => void }) {
  const notes = Notices(row)
  return (
    <div data-store-app={row.id} {...stylex.props(styles.item)}>
      <div {...stylex.props(styles.itemRow)}>
        <button
          type="button"
          onClick={onShow}
          aria-label={`Chi tiết ${row.name}`}
          {...stylex.props(styles.bare, shared.press)}
        >
          <Icon row={row} />
        </button>
        <button type="button" onClick={onShow} {...stylex.props(styles.info, styles.bare)}>
          <span {...stylex.props(styles.name)}>{row.name}</span>
          <span {...stylex.props(styles.sub)}>
            {row.author} · {version(row)}
          </span>
          <span {...stylex.props(styles.perms)}>
            {row.development ? (
              <span {...stylex.props(styles.tag, styles.tagDev)}>DEV</span>
            ) : row.lane === 'official' ? (
              <span {...stylex.props(styles.tag, styles.tagOfficial)}>
                <Sym name="check" size={10} />
                Chính thức
              </span>
            ) : (
              <span {...stylex.props(styles.tag)}>Cộng đồng</span>
            )}
            {row.permissions.map((p) => (
              <span key={p} title={PERM_LABEL[p] ?? p} {...stylex.props(styles.tag)}>
                <Sym name={PERM_GLYPH[p] ?? 'lock'} size={10} />
                {PERM_LABEL[p] ?? p}
              </span>
            ))}
          </span>
        </button>
        <Action row={row} store={store} open={open} />
      </div>
      {notes && <div {...stylex.props(styles.itemTail)}>{notes}</div>}
    </div>
  )
}

/** Error and staged-update notices under a row; Restore lives on the detail page. */
function Notices(row: StoreRow): ReactNode {
  const parts: ReactNode[] = []
  if (row.error)
    parts.push(
      <span key="e" role="alert" {...stylex.props(styles.alert)}>
        {row.error}
      </span>
    )
  if (row.candidate && !row.development)
    parts.push(
      <span key="c" {...stylex.props(styles.note)}>
        Cập nhật khi {row.name} đóng
      </span>
    )
  return parts.length ? parts : null
}

/** GET, OPEN, UPDATE, Retry update, a download ring or a reload prompt, whatever the row is in. */
function Action({ row, store, open, light }: { row: StoreRow; store: Store; open: Open; light?: boolean }) {
  const pill = (label: string, onClick: () => void, filled = false) => (
    <button
      type="button"
      onClick={onClick}
      {...stylex.props(styles.pill, filled && styles.pillFilled, light && !filled && styles.pillLight)}
    >
      {label}
    </button>
  )
  if (!row.compatible)
    return (
      <div {...stylex.props(styles.action)}>
        {pill('Tải lại nền tảng', () => location.reload())}
        <span {...stylex.props(styles.pct)}>Cần Duo mới hơn</span>
      </div>
    )
  if (row.progress !== undefined)
    return (
      <div {...stylex.props(styles.action)}>
        <div
          role="progressbar"
          aria-label={`Đang tải ${row.name}`}
          aria-valuenow={Math.round(row.progress * 100)}
          {...stylex.props(styles.ring(row.progress))}
        >
          <i {...stylex.props(styles.ringHole)} />
          <i {...stylex.props(styles.ringStop)} />
        </div>
        <span {...stylex.props(styles.pct)}>{Math.round(row.progress * 100)}%</span>
      </div>
    )
  if (!row.installed)
    return (
      <div {...stylex.props(styles.action)}>
        {pill('LẤY', () => {
          void store.install(row.id)
        })}
        <span {...stylex.props(styles.pct)}>{size(row.bytes)}</span>
      </div>
    )
  if (PREVIEW_FEATURES.stageUpdates && !row.development && needsRetry(row))
    return (
      <div {...stylex.props(styles.action)}>
        {pill('Thử lại', () => {
          void store.retry(row.id)
        })}
      </div>
    )
  if (hasUpdate(row) && !row.candidate)
    return (
      <div {...stylex.props(styles.action)}>
        {pill(
          'CẬP NHẬT',
          () => {
            void store.install(row.id)
          },
          true
        )}
        <span {...stylex.props(styles.pct)}>{row.version?.split('+')[0]}</span>
      </div>
    )
  return <div {...stylex.props(styles.action)}>{pill('MỞ', () => open(row.id))}</div>
}

function Icon({ row, xstyle }: { row: StoreRow; xstyle?: stylex.StyleXStyles }) {
  return row.icon ? (
    <img src={row.icon} alt="" {...stylex.props(styles.icon, xstyle)} />
  ) : (
    <span aria-hidden="true" {...stylex.props(styles.icon, styles.iconArt(art(row.name)), xstyle)}>
      {row.name[0]}
    </span>
  )
}

function Detail({
  id,
  store,
  open,
  openExternal,
  back
}: {
  id: string
  store: Store
  open: Open
  openExternal: External
  back: () => void
}) {
  const state = useSyncExternalStore(store.subscribe, store.snapshot)
  const row = state.rows.find((r) => r.id === id)
  if (!row)
    return (
      <Page title="App" back={back}>
        <Placeholder>App này không còn được liệt kê.</Placeholder>
      </Page>
    )
  const facts: [string, ReactNode, string?][] = [
    [
      'Phiên bản',
      version(row),
      row.installed && row.version !== row.installed ? `Đã có ${row.version?.split('+')[0]}` : 'Hiện tại'
    ],
    ['Dung lượng', size(row.bytes), 'Tải về'],
    ['Nhóm', row.lane === 'official' ? 'Chính thức' : row.lane === 'community' ? 'Cộng đồng' : 'Xem trước', row.author],
    ['Giấy phép', 'MIT', 'Mã nguồn mở'],
    [
      'Quyền truy cập',
      row.permissions.length ? String(row.permissions.length) : <Sym key="lock" name="lock" size={16} />,
      row.permissions.length ? 'quyền' : 'Trong sandbox'
    ]
  ]
  const notes = Notices(row)
  return (
    <Page title={row.name} back={back}>
      <div data-store-app={row.id}>
        <div {...stylex.props(styles.dHead)}>
          <Icon row={row} xstyle={styles.dIcon} />
          <div {...stylex.props(styles.dInfo)}>
            <div {...stylex.props(styles.dName)}>{row.name}</div>
            <div {...stylex.props(styles.dAuthor)}>{row.author}</div>
            <div {...stylex.props(styles.dActions)}>
              <Action row={row} store={store} open={open} />
              {row.repo && (
                <button
                  type="button"
                  aria-label="Xem mã nguồn"
                  {...stylex.props(styles.iconBtn, shared.press)}
                  onClick={() => openExternal(row.repo!)}
                >
                  <Sym name="share" size={15} />
                </button>
              )}
            </div>
          </div>
        </div>
        {notes && <div {...stylex.props(styles.para, styles.stack)}>{notes}</div>}
        <div {...stylex.props(styles.facts)}>
          {facts.map(([k, v, s]) => (
            <div key={k} {...stylex.props(styles.fact)}>
              <span {...stylex.props(styles.factK)}>{k}</span>
              <span {...stylex.props(styles.factV)}>{v}</span>
              {s && <span {...stylex.props(styles.factS)}>{s}</span>}
            </div>
          ))}
        </div>
        {row.note && (
          <>
            <div {...stylex.props(styles.h, styles.hTitle)}>Có gì mới</div>
            <p {...stylex.props(styles.para)}>{row.note}</p>
          </>
        )}
        <div {...stylex.props(styles.h, styles.hTitle)}>Quyền riêng tư</div>
        <Section>
          {row.permissions.length ? (
            row.permissions.map((p) => (
              <div key={p} {...stylex.props(shared.row)}>
                <span {...stylex.props(styles.permGlyph)}>
                  <Sym name={PERM_GLYPH[p] ?? 'lock'} size={16} />
                </span>
                <span {...stylex.props(styles.permText)}>{PERM_LABEL[p] ?? p}</span>
              </div>
            ))
          ) : (
            <div {...stylex.props(shared.row)}>
              <span {...stylex.props(styles.permGlyph)}>
                <Sym name="lock" size={16} />
              </span>
              <span {...stylex.props(styles.permText)}>Không truy cập thiết bị</span>
            </div>
          )}
        </Section>
        <p {...stylex.props(styles.footnote)}>
          {row.development
            ? 'Xem trước tại máy. Xóa app sẽ xóa luôn dữ liệu riêng của bản xem trước này.'
            : 'Chạy trong sandbox riêng: không camera, micro hay trang nhúng. Dữ liệu lưu ngay trên máy này.'}
          {row.recovery && ' Khôi phục để riêng các bản sửa mới hơn; bản sửa đó có thể thiếu trong phiên bản trước.'}
        </p>
        {row.installed && (row.recovery || !row.preinstalled) && (
          <Section>
            {row.recovery && (
              <button
                type="button"
                {...stylex.props(shared.row, styles.link, styles.linkBlue)}
                onClick={() => {
                  void store.restore(row.id)
                }}
              >
                <Sym name="undo" size={16} />
                Khôi phục phiên bản trước
              </button>
            )}
            {/* A preinstalled app reinstalls itself at the next start; removing it would undo itself. */}
            {!row.preinstalled && (
              <button
                type="button"
                {...stylex.props(shared.row, styles.remove)}
                onClick={() => {
                  void store.remove(row.id)
                  back()
                }}
              >
                <Sym name="trash" size={16} />
                Xóa app
              </button>
            )}
          </Section>
        )}
      </div>
    </Page>
  )
}

function Developer({
  store,
  openExternal,
  source,
  developer
}: {
  store: Store
  openExternal: External
  source: string
  developer: boolean
}) {
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  return (
    <>
      <div {...stylex.props(styles.h, styles.hTitle)}>Dành cho nhà phát triển</div>
      <Section aria-labelledby="for-developers" xstyle={styles.card}>
        <button
          type="button"
          data-store-submit
          {...stylex.props(shared.row, styles.link)}
          onClick={() => openExternal(SUBMIT_URL)}
        >
          <span {...stylex.props(styles.permGlyph, styles.glyphGreen)}>
            <Sym name="plus" size={16} />
          </span>
          <span id="for-developers" {...stylex.props(styles.permText)}>
            Gửi app của bạn
          </span>
          <span {...stylex.props(shared.rowR)}>›</span>
        </button>
        <form
          {...stylex.props(shared.row, styles.form)}
          onSubmit={(event) => {
            event.preventDefault()
            setError('')
            void store.loadCatalog(url).catch((e) => setError(String(e.message)))
          }}
        >
          <span {...stylex.props(styles.permText)}>Danh mục nhà phát triển</span>
          <label {...stylex.props(styles.field)}>
            <Sym name="tabs" size={14} />
            <input
              aria-label="URL danh mục nhà phát triển"
              type="url"
              placeholder="http://localhost:5173/index.json"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              required
              {...stylex.props(styles.searchInput)}
            />
          </label>
          <div {...stylex.props(styles.dActions, styles.noTop)}>
            <button type="submit" {...stylex.props(styles.pill, styles.pillFilled)}>
              Tải danh mục
            </button>
            {developer && (
              <button
                type="button"
                {...stylex.props(styles.pill)}
                onClick={() => {
                  void store.resetCatalog()
                }}
              >
                Quay lại danh mục Duo
              </button>
            )}
          </div>
          {error && (
            <span role="alert" {...stylex.props(styles.alert)}>
              {error}
            </span>
          )}
        </form>
      </Section>
      <p {...stylex.props(styles.footnote)}>
        Danh mục: {source}. Hãy cài app được đóng gói riêng. Hash danh mục kiểm tra bản tải xuống; hash không xác minh
        người phát hành.
      </p>
    </>
  )
}
