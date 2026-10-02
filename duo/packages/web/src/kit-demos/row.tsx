import { Row, Section, Sym, Toggle } from '@doan-labs/duo-uikit'
import { useState } from 'react'

export default function Demo() {
  const [taps, setTaps] = useState(0)
  return (
    <Section>
      <Row label="Chỉ có nhãn" />
      <Row label="Kèm chi tiết" detail="Giá trị" />
      <Row icon={<Sym name="gear" />} label="Icon và mũi tên" chevron />
      <Row label="Kèm nút điều khiển">
        <Toggle aria-label="Công tắc ví dụ" defaultChecked />
      </Row>
      <Row
        as="button"
        label="Là nút bấm"
        detail={taps ? `${taps} lần chạm` : undefined}
        onClick={() => setTaps((n) => n + 1)}
        chevron
      />
    </Section>
  )
}
