import { Placeholder, Row, Text } from '@doan-labs/duo-uikit'
import { Nav, Page, useNav } from '@doan-labs/duo-uikit/nav.tsx'
import { shared } from '@doan-labs/duo-uikit/styles.ts'
import * as stylex from '@stylexjs/stylex'
import { styles } from './styles.ts'

/** name, emoji, children — a leaf is a file, anything with children is a folder. */
type Node_ = { n: string; i: string; kids?: Node_[]; size?: string }
const FILES: Node_[] = [
  {
    n: 'iCloud Drive',
    i: '☁️',
    kids: [
      {
        n: 'Freeform',
        i: '📁',
        kids: [
          { n: 'Bản sketch bản lề', i: '🖼', size: '1.2 MB' },
          { n: 'Vát cạnh ray', i: '🖼', size: '840 KB' }
        ]
      },
      { n: 'Keynote', i: '📁', kids: [{ n: 'Ra mắt Duo.key', i: '📊', size: '48.3 MB' }] },
      {
        n: 'Ảnh chụp màn hình',
        i: '📁',
        kids: [
          { n: 'inner@2x.png', i: '🖼', size: '2.1 MB' },
          { n: 'outer@2x.png', i: '🖼', size: '1.4 MB' }
        ]
      },
      { n: 'Specs.pdf', i: '📕', size: '312 KB' }
    ]
  },
  {
    n: 'Trên iPhone của tôi',
    i: '📱',
    kids: [
      { n: 'Ghi âm', i: '📁', kids: [{ n: 'Bản ghi 1.m4a', i: '🎙', size: '2.8 MB' }] },
      { n: 'Tải xuống', i: '📁', kids: [{ n: 'iPhone_Duo.usdz', i: '🧊', size: '8.1 MB' }] }
    ]
  },
  { n: 'Đã xóa gần đây', i: '🗑', kids: [] }
]

/** A folder as an icon grid, or a file as its emoji and size. */
const Node = ({ node, back }: { node: Node_; back: () => void }) => {
  const { push } = useNav()
  const kids = node.kids ?? []
  return (
    <Page title={node.n} back={back}>
      {kids.length ? (
        <div {...stylex.props(styles.dz)}>
          {kids.map((k) => (
            <div key={k.n} {...stylex.props(styles.f)} onClick={() => push((b) => <Node node={k} back={b} />)}>
              <i {...stylex.props(styles.fIcon)}>{k.i}</i>
              <span>{k.n}</span>
              {k.size && (
                <Text size="caption" xstyle={[styles.size]}>
                  {k.size}
                </Text>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Placeholder>
          {node.size ? <div {...stylex.props(styles.bigIcon)}>{node.i}</div> : ''}
          {node.size ?? 'Trống'}
        </Placeholder>
      )}
      {kids.length ? <Text as="div" size="caption" xstyle={[styles.count]}>{`${kids.length} mục`}</Text> : null}
    </Page>
  )
}

const Browse = () => {
  const { push } = useNav()
  return (
    <Page title="Duyệt">
      <div {...stylex.props(styles.sec)}>ĐỊA ĐIỂM</div>
      {FILES.map((f) => (
        <Row key={f.n} onClick={() => push((b) => <Node node={f} back={b} />)}>
          <span {...stylex.props(styles.locIcon)}>{f.i}</span>
          {f.n}
          <span {...stylex.props(shared.rowR)}>›</span>
        </Row>
      ))}
    </Page>
  )
}

export const Files = () => (
  <Nav>
    <Browse />
  </Nav>
)
