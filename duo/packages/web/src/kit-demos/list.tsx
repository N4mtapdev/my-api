import { List, Row, Section, Sym } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <Section>
      <List aria-label="Kết nối">
        <Row as="li" icon={<Sym name="wifi" />} label="Wi-Fi" detail="Home" chevron />
        <Row as="li" icon={<Sym name="bluetooth" />} label="Bluetooth" detail="Bật" chevron />
        <Row as="li" icon={<Sym name="cellular" />} label="Di động" chevron />
      </List>
    </Section>
  )
}
