import { LargeTitle, Row, Section } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <>
      <LargeTitle as="h1">Cài đặt</LargeTitle>
      <Section>
        <Row label="Cài đặt chung" chevron />
        <Row label="Màn hình và Độ sáng" chevron />
      </Section>
    </>
  )
}
