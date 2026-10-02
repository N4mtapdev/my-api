import * as stylex from '@stylexjs/stylex'
import { createFileRoute, Link } from '@tanstack/react-router'
import { versions } from '../generated/api'
import { kit } from '../kit/data'
import { Prose } from '../layout'
import { Code, PageTop, Pre, Reveal } from '../page-parts'
import { blob } from '../site'
import { color, ease, font, radius } from '../tokens.stylex'

export const Route = createFileRoute('/kit/docs/')({
  head: () => ({ meta: [{ title: 'Tham chiếu UI kit · Duo' }] }),
  component: Index
})

// Components first, then hooks; types close the list.
const KIND_ORDER = ['component', 'hook', 'function', 'value', 'class', 'type']
const listed = [...kit].sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind))

function Index() {
  return (
    <Prose>
      <PageTop
        eyebrow="Tham chiếu"
        title="UI kit"
        lead={
          <>
            <Code>@doan-labs/duo-uikit</Code>: component và token mà mọi app trên máy được dựng nên từ đó. Chúng sinh ra
            đã hiểu màn hình ngoài lẫn màn hình trong, nên khung hình đọc tốt ở 387 điểm sẽ lớn lên thành không gian
            đầy đủ khi máy được mở ra.
          </>
        }
      />
      <Pre lang="tsx">{`import {
  Button, Row, Screen, Section, Text, Title, useDisplay
} from '@doan-labs/duo-uikit'

function App() {
  const view = useDisplay()
  return (
    <Screen>
      <Title>Field guide</Title>
      <Section>
        <Row label="Display" detail={view.display} />
        <Row label="Fold" detail={<Text value={view.angle} suffix="°" />} />
        <Row><Button onClick={save}>Continue</Button></Row>
      </Section>
    </Screen>
  )
}`}</Pre>
      <p {...stylex.props(styles.p)}>
        Phiên bản <Code>{versions.uikit?.version}</Code>. App đóng gói luôn bản kit mà nó biên dịch cùng, nên phiên bản
        mới không bao giờ làm thay đổi việc máy có chạy được app đã cài hay không. Component nhận thuộc tính native,{' '}
        <Code>as</Code> để chọn element, <Code>animate</Code> cho các preset CSS thuần và <Code>xstyle</Code> cho phần
        mở rộng StyleX đã biên dịch, và từ chối <Code>style</Code> cùng <Code>className</Code> thô. Trang{' '}
        <Link to="/kit" {...stylex.props(styles.link)}>
          showcase
        </Link>{' '}
        chạy mọi component trực tiếp, còn{' '}
        <a href={blob('examples/developer/main.tsx')} {...stylex.props(styles.link)}>
          Developer gallery
        </a>{' '}
        là một app cài được, render mọi export ở cả hai bề rộng màn hình.
      </p>
      <Reveal>
        <h2 {...stylex.props(styles.h2)}>Danh sách export</h2>
        <ul {...stylex.props(styles.list)}>
          {listed.map((e) => (
            <li key={e.name}>
              <Link to="/kit/docs/$name" params={{ name: e.name }} {...stylex.props(styles.row)}>
                <span {...stylex.props(styles.name)}>{e.name}</span>
                <span {...stylex.props(styles.kind)}>{e.kind}</span>
                <span {...stylex.props(styles.summary)}>{e.doc.split('\n')[0]}</span>
              </Link>
            </li>
          ))}
        </ul>
      </Reveal>
      <h2 {...stylex.props(styles.h2)}>Tokens</h2>
      <p {...stylex.props(styles.p)}>
        Màu sắc, kiểu chữ và độ nảy nằm trong{' '}
        <a href={blob('packages/uikit/tokens.stylex.ts')} {...stylex.props(styles.link)}>
          tokens.stylex.ts
        </a>{' '}
        dưới dạng biến StyleX. Dùng token, đừng dùng số cứng: hai màn hình có mật độ khác nhau, shell tự tinh chỉnh
        bảng màu cho cả hai, và chính quy tắc đó khiến một lần sửa trong kit lan tới mọi app.
      </p>
    </Prose>
  )
}

const styles = stylex.create({
  p: { fontSize: '17px', lineHeight: 1.6, marginTop: 0, marginBottom: '16px' },
  h2: {
    fontFamily: font.mono,
    fontSize: '11px',
    fontWeight: 500,
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    color: color.text3,
    marginTop: '36px',
    marginBottom: '10px'
  },
  list: { listStyleType: 'none', margin: 0, padding: 0, marginBottom: '16px', display: 'grid', gap: '8px' },
  row: {
    display: 'flex',
    alignItems: 'baseline',
    flexWrap: 'wrap',
    gap: '12px',
    paddingTop: '14px',
    paddingBottom: '14px',
    paddingLeft: '18px',
    paddingRight: '18px',
    backgroundColor: color.surface,
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: { default: color.border, ':hover': color.borderStrong },
    borderRadius: radius.md,
    textDecoration: 'none',
    willChange: 'transform',
    transitionProperty: 'border-color, transform, box-shadow, outline-color',
    transitionDuration: '0.25s',
    transitionTimingFunction: ease.out,
    transform: { default: 'translateY(0)', ':hover': 'translateY(-2px)' },
    boxShadow: { default: 'none', ':hover': color.shadow },
    outlineColor: { default: 'transparent', ':focus-visible': color.ring },
    outlineStyle: 'solid',
    outlineWidth: '2px',
    outlineOffset: '2px'
  },
  name: { fontFamily: font.mono, fontSize: '15px', fontWeight: 500, color: color.accent },
  kind: {
    fontFamily: font.mono,
    fontSize: '10.5px',
    fontWeight: 500,
    lineHeight: 1,
    color: color.text3,
    backgroundColor: color.grayBg,
    borderRadius: radius.pill,
    paddingTop: '5px',
    paddingBottom: '5px',
    paddingLeft: '9px',
    paddingRight: '9px',
    textTransform: 'uppercase',
    letterSpacing: '0.1em'
  },
  summary: { fontSize: '15px', lineHeight: 1.5, color: color.text2, flexBasis: '100%' },
  link: {
    color: { default: color.accent, ':hover': color.accentHover },
    textDecoration: { default: 'none', ':hover': 'underline' },
    textUnderlineOffset: '3px',
    borderRadius: '4px',
    outlineColor: { default: 'transparent', ':focus-visible': color.ring },
    outlineStyle: 'solid',
    outlineWidth: '2px',
    outlineOffset: '3px'
  }
})
