import { LargeTitle, Row, Screen, Section, Title } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <>
      <Title as="h1">Ghi chú</Title>
      <Screen aria-label="Ghi chú">
        <LargeTitle>Mọi ghi chú</LargeTitle>
        <Section>
          <Row label="Đi chợ" detail="Hôm nay" chevron />
          <Row label="Danh sách hành lý" detail="Hôm qua" chevron />
          <Row label="Ý tưởng" detail="Thứ Hai" chevron />
        </Section>
      </Screen>
    </>
  )
}
