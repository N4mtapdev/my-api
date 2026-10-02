import { Button, Row, Section, Sym } from '@doan-labs/duo-uikit'
import { useState } from 'react'

export default function Demo() {
  const [pressed, setPressed] = useState('Chưa bấm nút nào')
  return (
    <Section>
      <Row>
        <Button variant="filled" onClick={() => setPressed('Đặc')}>
          Đặc
        </Button>
        <Button onClick={() => setPressed('Nhạt')}>Nhạt</Button>
        <Button variant="plain" onClick={() => setPressed('Trơn')}>
          Trơn
        </Button>
      </Row>
      <Row>
        <Button disabled>Vô hiệu</Button>
        <Button aria-label="Cài đặt" onClick={() => setPressed('Biểu tượng')}>
          <Sym name="gear" />
        </Button>
      </Row>
      <Row label="Vừa bấm" detail={pressed} />
    </Section>
  )
}
