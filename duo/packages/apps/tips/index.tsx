import { LargeTitle, Screen, Text } from '@doan-labs/duo-uikit'
import { delay, shared } from '@doan-labs/duo-uikit/styles.ts'
import { appAppearance } from '@doan-labs/duo-uikit/tokens.stylex.ts'
import * as stylex from '@stylexjs/stylex'
import { useState } from 'react'
import { styles } from './styles.ts'

const TIPS: [string, string, string, string][] = [
  [
    'Hai màn hình, một thao tác',
    '📖',
    appAppearance.tipsWarm,
    'Mở Duo ra thì thứ bạn đang đọc sẽ giãn sang màn hình trong. Gập lại, đúng khung hình đó bật về màn hình ngoài, giữ nguyên chỗ đọc.'
  ],
  [
    'Kéo qua bản lề',
    '🫳',
    appAppearance.tipsCool,
    'Nhấc một bức ảnh ở nửa bên trái rồi thả vào tin nhắn ở nửa bên phải. Hai app hai bên bản lề dùng chung một phiên kéo thả.'
  ],
  [
    'Gập nửa để chụp',
    '📸',
    appAppearance.tipsGreen,
    'Đặt Duo ở 90° thì khung nhìn chuyển lên nửa trên, phần điều khiển xuống nửa dưới. Chụp phơi sáng dài không cần tripod.'
  ],
  [
    'Widget màn hình ngoài',
    '🧩',
    appAppearance.tipsPink,
    'Widget đặt ở bốn cột bên trái vẫn nguyên vị trí khi gập máy, vì màn hình ngoài hiển thị đúng nửa đó.'
  ],
  [
    'Pin cho cả hai nửa',
    '🔋',
    appAppearance.tipsYellow,
    'Đóng Duo thì màn hình trong tắt hẳn. Chỉ đọc trên màn hình ngoài, một lần sạc gần như dùng được gấp đôi.'
  ]
]

const Tip = ({ title, emoji, bg, body, i }: { title: string; emoji: string; bg: string; body: string; i: number }) => {
  const [open, setOpen] = useState(false)
  return (
    <div {...stylex.props(styles.tip, shared.rise, delay.ms(i * 60))} onClick={() => setOpen(!open)}>
      <div {...stylex.props(styles.im, styles.bg(bg))}>{emoji}</div>
      <div {...stylex.props(styles.tx)}>
        <div {...stylex.props(styles.title)}>{title}</div>
        <Text as="div" size="caption" xstyle={[styles.hint]}>
          Chạm để đọc
        </Text>
        <p {...stylex.props(styles.more, open && styles.moreOpen)}>{body}</p>
      </div>
    </div>
  )
}

export const Tips = () => (
  <Screen>
    <LargeTitle>Mẹo</LargeTitle>
    <Text as="div" size="caption" xstyle={[styles.lede]}>
      Trải nghiệm iPhone Duo trọn vẹn hơn
    </Text>
    <div {...stylex.props(styles.cols)}>
      {TIPS.map(([title, emoji, bg, body], i) => (
        <Tip key={title} title={title} emoji={emoji} bg={bg} body={body} i={i} />
      ))}
    </div>
  </Screen>
)
