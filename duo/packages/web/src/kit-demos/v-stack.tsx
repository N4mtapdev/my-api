import { Placeholder, Row, Section, Title, VStack } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <VStack as="main">
      <Title as="h1">Ngăn xếp</Title>
      <Section>
        <Row label="Phần đầu đứng yên" />
      </Section>
      <Placeholder>Placeholder chiếm phần còn lại</Placeholder>
    </VStack>
  )
}
