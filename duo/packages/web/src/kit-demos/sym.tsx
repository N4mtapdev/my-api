import { Row, Section, Sym, Text } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <Section>
      <Row icon={<Sym name="wifi" />} label="Thừa màu của hàng" />
      <Row
        icon={
          <Text color="accent">
            <Sym name="location" size={22} />
          </Text>
        }
        label="Nhuộm màu qua Text"
      />
      <Row icon={<Sym name="lock" size={14} />} label="Cỡ theo điểm" />
    </Section>
  )
}
