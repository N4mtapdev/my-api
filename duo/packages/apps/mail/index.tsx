import { Screen, Text, Title, VStack } from '@doan-labs/duo-uikit'

// Mail. A fixed inbox; each message opens on a pushed page.

import { art, beep } from '@doan-labs/duo-fixtures'
import { Nav, Page, useNav } from '@doan-labs/duo-uikit/nav.tsx'
import { shared } from '@doan-labs/duo-uikit/styles.ts'
import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import * as stylex from '@stylexjs/stylex'
import { styles } from './styles.ts'

type Message = [who: string, subject: string, body: string, when: string]

const MAIL: Message[] = [
  [
    'Jony',
    'Re: độ rộng vát cạnh',
    'Hạ xuống còn 0,55 mm. Đường kẻ mảnh đã chuẩn — sống máy giữ sắc đen, chỉ mặt vát là hắt ánh đèn dải.',
    '9:12'
  ],
  [
    'Blender Foundation',
    'Cycles 5.2 đã ra mắt',
    'AgX là view transform mặc định. Nhóm compositor của bạn sẽ cần node Glare điều khiển qua socket; các thuộc tính cũ đã bỏ.',
    '8:40'
  ],
  [
    'App Store Connect',
    'Bản gửi của bạn đang được xem xét',
    'iPhone Duo 1.0 (build 41) đã vào hàng chờ xem xét. Chúng tôi sẽ báo khi có cập nhật.',
    'Hôm qua'
  ],
  [
    'Ada Lovelace',
    'Về Máy Giải tích',
    'Máy dệt những hoạ tiết đại số y như khung cửi Jacquard dệt hoa với lá. Đã kèm ghi chú.',
    'Hôm qua'
  ],
  ['Kim Minh', 'renders', 'gửi anh 4 tấm final nhé, hero với back đẹp nhất. macro hơi noisy, để em tăng sample.', 'T2'],
  [
    'TestFlight',
    'iPhone Duo — build 40 đã hết hạn',
    'Build này không còn để kiểm thử. Cài bản build mới nhất để tiếp tục kiểm thử.',
    'T2'
  ]
]

/** Hand-rolled rather than `Page`: the back button carries the "Inbox" label and the header is a size smaller. */
const Read = ({ m: [who, subj, body, when], back }: { m: Message; back: () => void }) => (
  <VStack>
    <Title xstyle={[styles.hdrMd]}>
      <button type="button" {...stylex.props(shared.bk)} onClick={back}>
        <Sym name="back" size={20} />
        Hộp thư
      </button>
      <Title as="span" variant="accessory" xstyle={[styles.actions]}>
        <Sym name="share" size={19} />
        <Sym name="more" size={19} />
      </Title>
    </Title>
    <Screen>
      <div {...stylex.props(styles.head)}>
        <div {...stylex.props(styles.subject)}>{subj}</div>
        <div {...stylex.props(styles.from)}>
          <div {...stylex.props(styles.avatar, styles.tint(art(who)))}>{who[0]}</div>
          <div>
            <div {...stylex.props(styles.name)}>{who}</div>
            <Text as="div" size="caption">
              gửi tôi
            </Text>
          </div>
          <Text size="caption" xstyle={[styles.when]}>
            {when}
          </Text>
        </div>
      </div>
      <div {...stylex.props(styles.artTxt)}>
        <p {...stylex.props(styles.para)}>{body}</p>
        <p {...stylex.props(styles.para)}>Gửi từ iPhone Duo của tôi — hai màn hình, một hình nền.</p>
      </div>
    </Screen>
  </VStack>
)

const Inbox = () => {
  const { push } = useNav()
  return (
    <div>
      {MAIL.map((m, i) => {
        const [who, subj, body, when] = m
        return (
          <div key={who + subj} {...stylex.props(styles.li)} onClick={() => push((back) => <Read m={m} back={back} />)}>
            {i < 2 ? <div {...stylex.props(styles.dot)} /> : <div {...stylex.props(styles.gutter)} />}
            <div {...stylex.props(styles.tx)}>
              <b {...stylex.props(styles.who)}>{who}</b>
              <div {...stylex.props(styles.subj)}>{subj}</div>
              <p {...stylex.props(styles.preview)}>{body}</p>
            </div>
            <Text size="caption" xstyle={[styles.noShrink]}>
              {when} ›
            </Text>
          </div>
        )
      })}
    </div>
  )
}

export const Mail = () => (
  <VStack xstyle={[styles.rel]}>
    <Nav>
      <Page
        title={
          <>
            Hộp thư
            <Title as="span" variant="accessory">
              {MAIL.length} thư
            </Title>
          </>
        }
      >
        <Inbox />
      </Page>
    </Nav>
    <button type="button" {...stylex.props(shared.fab)} onClick={() => beep([880, 1200], 0.07, 0.05)}>
      <Sym name="plus" size={22} />
    </button>
  </VStack>
)
