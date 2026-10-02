import { Row, Section, Title } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <>
      <Title as="h1">
        Nhắc việc
        <Title as="span" variant="accessory">
          3 việc tới hạn
        </Title>
      </Title>
      <Section>
        <Row label="Gọi bác sĩ thú y" />
      </Section>
    </>
  )
}
