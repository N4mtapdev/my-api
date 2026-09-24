// The smallest useful SDK: four primitives as four rows.
import * as stylex from '@stylexjs/stylex'
import { color, font } from '../tokens.stylex'
import { Block, Cap, Headline, Lede, Rise, Stagger, TextLink } from './parts'

const MID = '@media (max-width: 1068px)'

const API = [
  { area: 'Màn hình', sig: 'useDisplay()', text: 'Màn hình nào, kích thước, góc bản lề và trạng thái focus, theo thời gian thực.' },
  { area: 'Lưu trữ', sig: 'useKV()', text: 'Kho lưu trữ bền, có phiên bản, riêng tư cho từng app.' },
  { area: 'Giao diện', sig: 'os.commands', text: 'Một app, hai giao diện, một chủ sở hữu; phần còn lại gửi lệnh.' },
  { area: 'Liên kết', sig: 'os.open()', text: 'Bàn giao sang app khác trên máy, kèm tham số.' }
]

export function Sdk() {
  return (
    <Block labelledBy="sdk-title">
      {/* The three lines of the introduction arrive in reading order rather than as one slab. */}
      <Stagger gap={0.09} amount={0.4}>
        <Rise>
          <Cap>05 · SDK</Cap>
        </Rise>
        <Rise>
          <Headline id="sdk-title" lines={['Bốn nguyên thủy.', 'Toàn bộ giao diện của SDK.']} />
        </Rise>
        <Rise>
          <Lede>
            Đủ để xây một app thật, nhỏ đến mức đọc trong một phút. Phần còn lại là React và nền tảng bạn vốn đã biết.{' '}
            <TextLink to="/docs/sdk">Xem trang SDK</TextLink> cho client đầy đủ.
          </Lede>
        </Rise>
      </Stagger>
      {/* The rows are a list, so they come in from the side: the eye reads down the
          rule while each signature slides up to it. */}
      <dl {...stylex.props(styles.list)}>
        <Stagger gap={0.08} amount={0.15} styles={styles.rows}>
          {API.map((a) => (
            <Rise key={a.sig} move="left" styles={styles.row}>
              <dt {...stylex.props(styles.area)}>{a.area}</dt>
              <dd {...stylex.props(styles.sig)}>{a.sig}</dd>
              <dd {...stylex.props(styles.text)}>{a.text}</dd>
            </Rise>
          ))}
        </Stagger>
      </dl>
    </Block>
  )
}

const styles = stylex.create({
  list: { margin: 0 },
  rows: { marginTop: '72px', borderTopWidth: '1px', borderTopStyle: 'solid', borderTopColor: color.border },
  row: {
    display: 'grid',
    gridTemplateColumns: { default: 'minmax(0, 2fr) minmax(0, 4fr) minmax(0, 6fr)', [MID]: 'minmax(0, 1fr)' },
    alignItems: 'baseline',
    gap: { default: '32px', [MID]: '8px' },
    paddingTop: '32px',
    paddingBottom: '32px',
    borderBottomWidth: '1px',
    borderBottomStyle: 'solid',
    borderBottomColor: color.border
  },
  area: {
    fontFamily: font.mono,
    fontSize: '12px',
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: color.text3
  },
  sig: {
    margin: 0,
    fontFamily: font.mono,
    fontSize: { default: '30px', [MID]: '24px' },
    fontWeight: 500,
    letterSpacing: '-0.02em',
    color: color.text
  },
  text: { margin: 0, fontSize: '18px', lineHeight: 1.5, color: color.text2 }
})
