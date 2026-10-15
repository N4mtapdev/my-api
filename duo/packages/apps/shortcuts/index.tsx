import { art, beep } from '@doan-labs/duo-fixtures'
import type { Os } from '@doan-labs/duo-sdk'
import { LargeTitle, Row, Screen, Section, Title } from '@doan-labs/duo-uikit'
import { shared } from '@doan-labs/duo-uikit/styles.ts'
import * as stylex from '@stylexjs/stylex'
import { useState } from 'react'
import { styles } from './styles.ts'

const Card = ({ name, glyph, act }: { name: string; glyph: string; act: () => void }) => {
  const [ran, setRan] = useState(false)
  const run = () => {
    setRan(true)
    beep([880, 1320], 0.06, 0.05)
    setTimeout(() => {
      setRan(false)
      act()
    }, 420)
  }
  return (
    <button type="button" {...stylex.props(styles.sc, styles.bg(art(name, 52)))} onClick={run}>
      <div {...stylex.props(styles.glyph)}>{glyph}</div>
      <b {...stylex.props(styles.name)}>{name}</b>
      <div {...stylex.props(styles.ok, ran && styles.okOn)}>✓</div>
    </button>
  )
}

export const Shortcuts = ({ os }: { os: Os }) => (
  <Screen>
    <LargeTitle>Phím tắt</LargeTitle>
    <div {...stylex.props(styles.scs)}>
      <Card
        name="Mở Wikipedia"
        glyph="🌐"
        act={() => os.open('Safari', 'https://en.m.wikipedia.org/wiki/Special:Random')}
      />
      <Card name="Chụp ảnh" glyph="📸" act={() => os.open('Camera')} />
      <Card name="Phát nhạc" glyph="🎧" act={() => os.open('Music')} />
      <Card name="Tin tức hôm nay" glyph="📰" act={() => os.open('News')} />
      <Card name="Gọi về nhà" glyph="☎️" act={() => os.open('Phone')} />
      <Card name="Tìm Duo của tôi" glyph="📍" act={() => os.open('Find My')} />
      <Card name="Bắt đầu vẽ" glyph="✏️" act={() => os.open('Freeform')} />
      <Card name="Về Màn hình chính" glyph="🏠" act={() => os.home()} />
    </div>
    <Title xstyle={[styles.hdrSm]}>Tự động hóa</Title>
    <Section>
      <Row>
        Khi điện thoại mở ra
        <span {...stylex.props(shared.rowR)}>Mở Freeform ›</span>
      </Row>
      <Row>
        Lúc hoàng hôn
        <span {...stylex.props(shared.rowR)}>Giảm đèn Key Light ›</span>
      </Row>
      <Row>
        Khi bản render xong
        <span {...stylex.props(shared.rowR)}>Phát âm thanh ›</span>
      </Row>
    </Section>
  </Screen>
)
