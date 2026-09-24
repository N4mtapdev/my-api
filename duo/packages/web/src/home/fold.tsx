// The core idea: the fold is input. Four postures the visitor can pick; the
// real shell eases to each, the line of code that posture would run lights
// up, and a readout shows what `useDisplay()` hands the app in that state.
import * as stylex from '@stylexjs/stylex'
import { useState } from 'react'
import { Line } from '../highlight'
import { Segmented } from '../segmented'
import { Simulator } from '../simulator'
import { color, font } from '../tokens.stylex'
import { Block, Cap, Columns, Headline, Lede } from './parts'

const SMALL = '@media (max-width: 734px)'

type Posture = { deg: number; name: string; display: 'inner' | 'cover'; size: string; runs: number }
const OPEN: Posture = { deg: 180, name: 'Mở hết cỡ', display: 'inner', size: '790 × 850', runs: 4 }
const STATES: Posture[] = [
  OPEN,
  { deg: 120, name: 'Gập một phần', display: 'inner', size: '790 × 850', runs: 3 },
  { deg: 90, name: 'Đặt bàn', display: 'inner', size: '790 × 850', runs: 3 },
  { deg: 0, name: 'Gập kín', display: 'cover', size: '387 × 850', runs: 2 }
]

// What `useDisplay()` really returns: display, placement, size and the hinge
// angle. `runs` above points at the line each posture reaches.
const CODE = [
  'const { display, angle, width, height } = useDisplay()',
  '',
  "if (display === 'cover') return <PocketCard />",
  'if (angle < 150) return <Workspace angle={angle} />',
  'return <Board width={width} height={height} />'
]

export function Fold() {
  // The hinge angle is the identity of a posture, so the control can key on a plain value.
  const [deg, setDeg] = useState(OPEN.deg)
  const s = STATES.find((st) => st.deg === deg) ?? OPEN

  return (
    <Block cinema labelledBy="fold-title">
      <Cap>04 · Ý tưởng cốt lõi</Cap>
      <Headline id="fold-title" lines={['Độ gập không phải breakpoint.', 'Nó là dữ liệu đầu vào.']} />
      <Lede>
        Phần mềm responsive thường chỉ hỏi: màn hình rộng bao nhiêu? Duo còn hỏi máy đang ở dáng nào, và báo cho app
        của bạn mỗi khi điều đó thay đổi.
      </Lede>

      <div {...stylex.props(styles.scene)}>
        <Columns align="start">
          <div>
            <Segmented
              id="fold-posture"
              label="Tư thế"
              value={deg}
              onChange={(d) => setDeg(d)}
              options={STATES.map((st) => ({ value: st.deg, label: st.name }))}
            />

            <div {...stylex.props(styles.code)}>
              <div {...stylex.props(styles.codeTitle)}>app.tsx</div>
              <pre {...stylex.props(styles.pre)}>
                {CODE.map((line, i) => (
                  <div key={line || `blank-${i}`} {...stylex.props(styles.line, i === s.runs && styles.lineOn)}>
                    <span {...stylex.props(styles.gutter)}>{i + 1}</span>
                    <code {...stylex.props(styles.text)}>
                      <Line code={line} />
                    </code>
                  </div>
                ))}
              </pre>
            </div>

            <dl {...stylex.props(styles.readout)} aria-live="polite">
              <Field k="display" v={`"${s.display}"`} />
              <Field k="angle" v={String(s.deg)} />
              <Field k="placement" v={'"full"'} />
              <Field k="width × height" v={s.size} />
            </dl>
            <p {...stylex.props(styles.list)}>
              App được thông báo màn hình đang dùng, vị trí của mình trên đó, kích thước và góc bản lề, mỗi khi một
              giá trị thay đổi. Không gì khác; độ gập chính là API.
            </p>
          </div>
          <div {...stylex.props(styles.device)}>
            <Simulator deg={s.deg} bare />
          </div>
        </Columns>
      </div>
    </Block>
  )
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <div {...stylex.props(styles.field)}>
      <dt {...stylex.props(styles.key)}>{k}</dt>
      <dd {...stylex.props(styles.val)}>{v}</dd>
    </div>
  )
}

const styles = stylex.create({
  scene: { marginTop: { default: '72px', [SMALL]: '48px' } },
  code: {
    marginTop: '24px',
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: color.border,
    borderRadius: '14px',
    backgroundColor: color.surface,
    overflow: 'hidden'
  },
  codeTitle: {
    paddingTop: '10px',
    paddingBottom: '10px',
    paddingLeft: '18px',
    paddingRight: '18px',
    borderBottomWidth: '1px',
    borderBottomStyle: 'solid',
    borderBottomColor: color.border,
    fontFamily: font.mono,
    fontSize: '11.5px',
    letterSpacing: '0.04em',
    color: color.text3
  },
  pre: {
    margin: 0,
    paddingTop: '14px',
    paddingBottom: '14px',
    fontFamily: font.mono,
    fontSize: '13.5px',
    lineHeight: 1.7,
    color: color.text,
    overflowX: 'auto'
  },
  line: {
    display: 'flex',
    gap: '16px',
    paddingLeft: '14px',
    paddingRight: '18px',
    borderLeftWidth: '2px',
    borderLeftStyle: 'solid',
    borderLeftColor: 'transparent',
    transitionProperty: 'background-color, border-color',
    transitionDuration: '0.35s'
  },
  lineOn: { backgroundColor: color.accentSoft, borderLeftColor: color.accent },
  gutter: {
    flexShrink: 0,
    width: '1.5ch',
    textAlign: 'right',
    color: color.text3,
    userSelect: 'none'
  },
  text: { whiteSpace: 'pre', fontFamily: 'inherit' },
  readout: {
    margin: 0,
    marginTop: '16px',
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: '1px',
    backgroundColor: color.border,
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: color.border,
    borderRadius: '14px',
    overflow: 'hidden'
  },
  field: {
    backgroundColor: color.bg,
    paddingTop: '14px',
    paddingBottom: '14px',
    paddingLeft: '18px',
    paddingRight: '18px'
  },
  key: { fontFamily: font.mono, fontSize: '11px', letterSpacing: '0.06em', color: color.text3 },
  val: {
    margin: 0,
    marginTop: '6px',
    fontFamily: font.mono,
    fontSize: '15px',
    color: color.text,
    transitionProperty: 'color',
    transitionDuration: '0.35s'
  },
  list: {
    marginTop: '28px',
    marginBottom: 0,
    maxWidth: '44ch',
    fontSize: '16px',
    lineHeight: 1.55,
    color: color.text2
  },
  device: { position: 'sticky', top: '96px', display: 'flex', justifyContent: 'center', alignItems: 'center' }
})
