// The end: one line, three buttons, and what Duo is in a sentence.
import * as stylex from '@stylexjs/stylex'
import { Button } from '../layout'
import { REPO } from '../site'
import { color } from '../tokens.stylex'
import { Block, Headline, Rise, Stagger } from './parts'

const ACTIONS = [
  { to: '/simulator', label: 'Dùng thử Duo' },
  { to: '/docs', label: 'Đọc tài liệu', outline: true },
  { href: REPO, label: 'Xem trên GitHub', outline: true }
]

export function Cta() {
  return (
    <Block labelledBy="cta-title">
      <Stagger gap={0.08} amount={0.4} styles={styles.centre}>
        <Rise>
          <Headline id="cta-title" lines={['Hãy xây thử thứ gì đó lạ lạ', 'cho chiếc máy biết gập.']} />
        </Rise>
        {/* A plain row, not a second `Stagger`: motion carries the variant down
            through the DOM, so the three buttons are beats of the same sequence
            and land one at a time, left to right. */}
        <div {...stylex.props(styles.actions)}>
          {ACTIONS.map((a) => (
            <Rise key={a.label} move="in" styles={styles.action}>
              <Button to={a.to} href={a.href} outline={a.outline}>
                {a.label}
              </Button>
            </Rise>
          ))}
        </div>
        <Rise>
          <p {...stylex.props(styles.line)}>Duo là một thí nghiệm mở về phần mềm màn hình gập có thể trở thành gì.</p>
        </Rise>
      </Stagger>
    </Block>
  )
}

const styles = stylex.create({
  centre: { textAlign: 'center', maxWidth: '880px', marginLeft: 'auto', marginRight: 'auto' },
  actions: { display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '12px', marginTop: '40px' },
  action: { display: 'inline-flex' },
  line: { marginTop: '40px', marginBottom: 0, fontSize: '16px', color: color.text3 }
})
