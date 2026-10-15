import type { Os } from '@doan-labs/duo-sdk'
import { Row as KitRow, Screen, Section, Text, Title, Toggle } from '@doan-labs/duo-uikit'
import { Rings } from '@doan-labs/duo-uikit/rings.tsx'
import { shared } from '@doan-labs/duo-uikit/styles.ts'
import * as stylex from '@stylexjs/stylex'
import { type ReactNode, useEffect, useState } from 'react'
import { styles } from './styles.ts'

const now = () => {
  const d = new Date()
  return {
    t: d.toLocaleTimeString('vi', { hour: '2-digit', minute: '2-digit', hour12: false }),
    d: `${d.toLocaleDateString('vi', { weekday: 'short' })} ${d.getDate()}`.toUpperCase()
  }
}

const Row = ({ name, right }: { name: string; right: ReactNode }) => (
  <KitRow xstyle={[styles.darkRow]}>
    {name}
    <span {...stylex.props(shared.rowR)}>{right}</span>
  </KitRow>
)

export const Watch = (_: { os: Os }) => {
  const [clock, setClock] = useState(now)
  useEffect(() => {
    const iv = setInterval(() => setClock(now()), 1000)
    return () => clearInterval(iv)
  }, [])
  return (
    <Screen>
      <div {...stylex.props(styles.face)}>
        <div {...stylex.props(styles.date)}>{clock.d}</div>
        <div {...stylex.props(styles.time)}>{clock.t}</div>
        <div {...stylex.props(styles.mini)}>
          <Rings size={120} stroke={11} />
        </div>
      </div>
      <div {...stylex.props(styles.center)}>
        <div {...stylex.props(styles.name)}>Apple Watch Ultra</div>
        <Text as="div" size="caption">
          Đã kết nối · 78%
        </Text>
      </div>
      <Title xstyle={[styles.hdrSm]}>Đồng hồ của tôi</Title>
      <Section>
        <Row name="Thông báo" right="›" />
        <Row name="Bố cục app" right="Lưới ›" />
        <Row name="Biến phức tạp" right="4 ›" />
        <Row name="Phát hiện cổ tay" right={<Toggle aria-label="Phát hiện cổ tay" defaultChecked />} />
        <Row name="Chế độ rạp chiếu" right={<Toggle aria-label="Chế độ rạp chiếu" />} />
      </Section>
    </Screen>
  )
}
