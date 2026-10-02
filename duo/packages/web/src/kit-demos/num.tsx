import { Num, Row, Section } from '@doan-labs/duo-uikit'
import { useEffect, useState } from 'react'

export default function Demo() {
  const [steps, setSteps] = useState(8412)
  useEffect(() => {
    const t = setInterval(() => setSteps((s) => s + 7), 1500)
    return () => clearInterval(t)
  }, [])
  return (
    <Section>
      <Row label="Số bước" detail={<Num value={steps} />} />
      <Row
        label="Quãng đường"
        detail={<Num value={steps * 0.00074} format={{ maximumFractionDigits: 2 }} suffix=" km" />}
      />
      <Row label="Không có dữ liệu" detail={<Num value={undefined} />} />
    </Section>
  )
}
