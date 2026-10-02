import { Row, Section, Text } from '@doan-labs/duo-uikit'

export default function Demo() {
  return (
    <Section>
      <Row label="Thân bài" detail={<Text>Chữ thường</Text>} />
      <Row label="Chú thích" detail={<Text size="caption">Nhãn phụ</Text>} />
      <Row label="Chú thích cuối" detail={<Text size="footnote">Chú thích cuối</Text>} />
      <Row
        label="Tiêu đề"
        detail={
          <Text size="title2" weight="bold">
            Tiêu đề
          </Text>
        }
      />
      <Row
        label="Màu nhấn"
        detail={
          <Text color="accent" weight="medium">
            Nhuộm màu
          </Text>
        }
      />
      <Row label="Số" detail={<Text value={1234.5} format={{ maximumFractionDigits: 1 }} suffix=" đơn vị" />} />
    </Section>
  )
}
