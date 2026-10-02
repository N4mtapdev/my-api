import { Row, Section, Toggle } from '@doan-labs/duo-uikit'
import { useState } from 'react'

export default function Demo() {
  const [on, setOn] = useState(true)
  return (
    <Section>
      <Row label="Chế độ máy bay">
        <Toggle aria-label="Chế độ máy bay" checked={on} onChange={(e) => setOn(e.target.checked)} />
      </Row>
      <Row label="Vô hiệu">
        <Toggle aria-label="Công tắc vô hiệu" checked disabled />
      </Row>
    </Section>
  )
}
