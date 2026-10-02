import { Nav, NavigationLink, Row, Section, Text, Title } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <Nav>
      <Title as="h1">Chuyến đi</Title>
      <Section>
        <Row>
          <NavigationLink title="Lisbon" destination={<Text as="p">Quay lại trả tiêu điểm về liên kết.</Text>}>
            Mở Lisbon
          </NavigationLink>
        </Row>
      </Section>
    </Nav>
  )
}
