import { Button, HStack, Row, Section, Sym, Text } from '@doan-labs/duo-uikit'
import * as stylex from '@stylexjs/stylex'

export default function Demo() {
  return (
    <Section>
      <Row>
        <HStack gap={8}>
          <Button variant="filled">Lưu</Button>
          <Button>Để sau</Button>
        </HStack>
      </Row>
      <Row>
        <HStack gap={10} justify="between" xstyle={styles.fill}>
          <Text>Đẩy ra hai bên</Text>
          <Text color="secondary">nhờ justify</Text>
        </HStack>
      </Row>
      <Row>
        <HStack gap={6}>
          <Sym name="wifi" size={15} />
          <Text size="subheadline">Căn giữa theo trục ngang</Text>
        </HStack>
      </Row>
    </Section>
  )
}

const styles = stylex.create({ fill: { width: '100%' } })
