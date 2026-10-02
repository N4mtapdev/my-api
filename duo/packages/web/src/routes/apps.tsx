import * as stylex from '@stylexjs/stylex'
import { createFileRoute, Link } from '@tanstack/react-router'
import { Browser } from '../home/apps'
import { Block, Cap, Headline, Lede } from '../home/parts'
import { Button } from '../layout'
import { color, ease } from '../tokens.stylex'

export const Route = createFileRoute('/apps')({
  head: () => ({ meta: [{ title: 'Ứng dụng · Duo' }] }),
  component: Page
})

function Page() {
  return (
    <Block labelledBy="apps-title">
      <Cap>Ứng dụng</Cap>
      <Headline as="h1" id="apps-title" lines={['Sinh ra cho cả hai màn hình', 'và nếp gấp ở giữa.']} />
      <Lede>
        App chính thức có sẵn trong simulator và phát hành lên catalog của Duo; app cộng đồng được gửi qua pull
        request, review và phát hành đúng quy trình đó. Tất cả giấy phép MIT, cài qua App Store.{' '}
        <Link to="/publish" {...stylex.props(styles.link)}>
          Cách thêm app của bạn.
        </Link>
      </Lede>
      <div {...stylex.props(styles.action)}>
        <Button to="/publish">Gửi app của bạn</Button>
      </div>
      <Browser />
    </Block>
  )
}

const styles = stylex.create({
  link: {
    color: { default: color.text, ':hover': color.accent },
    textDecorationLine: 'underline',
    textUnderlineOffset: '3px',
    borderRadius: '4px',
    transitionProperty: 'color, outline-color',
    transitionDuration: '0.18s',
    transitionTimingFunction: ease.out,
    outlineColor: { default: 'transparent', ':focus-visible': color.ring },
    outlineStyle: 'solid',
    outlineWidth: '2px',
    outlineOffset: '3px'
  },
  action: { marginTop: '28px' }
})
