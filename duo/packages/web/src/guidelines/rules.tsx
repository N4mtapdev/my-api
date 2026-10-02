// The three rules and the iOS shortlist, on a reading measure rather than the
// full token grid: this is the one tab that is prose.
import * as stylex from '@stylexjs/stylex'
import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { color, ease, font, radius } from '../tokens.stylex'

// StyleX 0.19 cannot resolve an imported string as a media-query key, so the
// shared breakpoint is declared here (see tokens.stylex.ts).
const SMALL = '@media (max-width: 734px)'

export function Rules() {
  return (
    <div {...stylex.props(styles.measure)}>
      <ol {...stylex.props(styles.rules)}>
        <Rule n="1" title="Thiết kế cho màn hình ngoài trước">
          <p {...stylex.props(styles.p)}>
            Màn hình ngoài rộng 387 điểm; màn hình trong 790, hơn gấp đôi chút xíu. Bố cục đọc tốt trên màn hình ngoài
            thì khi mở máy có nơi để thở: danh sách thành danh sách đứng cạnh phần chi tiết, thanh công cụ trải ra, biểu
            đồ lấy lại được nhãn trục. Chiều ngược lại không bao giờ ổn: bố cục thiết kế cho màn hình trong mà nhồi vào
            màn hình ngoài là mất nút hoặc mất chữ.
          </p>
          <p {...stylex.props(styles.p)}>
            Dàn trang theo các hộp và để chiều rộng quyết định. Component của kit tự co lại ở độ rộng màn hình ngoài;
            component của bạn cũng nên vậy. Đừng bao giờ giấu một tính năng nào khỏi màn hình ngoài: người dùng có thể
            chẳng bao giờ mở máy ra để tìm nó.
          </p>
        </Rule>

        <Rule n="2" title="App của bạn chạy hai bản">
          <p {...stylex.props(styles.p)}>
            Trong khi máy đang dùng, màn hình kia giữ một bản chạy của app để việc gập - mở không phải remount hay chớp
            màn hình. Bản này vẽ lại tất cả nhưng không khởi động gì: không âm thanh, không gọi mạng, không bộ đếm của
            riêng nó. Trạng thái mà cả hai bản phải thống nhất thì nằm trong storage dùng chung, không nằm trong
            component.
          </p>
          <p {...stylex.props(styles.p)}>
            Thử là biết: mở app, gập máy hết cỡ, mở ra. Vẫn ghi chú đó, đúng vị trí cuộn đó, phát đúng một lần.
          </p>
        </Rule>

        <Rule n="3" title="Chỉ dùng token">
          <p {...stylex.props(styles.p)}>
            Mọi màu, cỡ chữ, bo góc và đường cong chuyển động lấy từ token của kit. Không hex, không cỡ chữ ghi bằng
            pixel. Đây không phải chuyện gu thẩm mỹ: hai màn hình có mật độ điểm khác nhau và shell tinh chỉnh bảng màu
            cho từng màn, app mà ghi số cứng thì nhìn sai ở một bên mà chẳng có gì chữa được.
          </p>
        </Rule>
      </ol>

      <h3 {...stylex.props(styles.h3)}>Và các quy tắc iOS vẫn có hiệu lực</h3>
      <ul {...stylex.props(styles.ul)}>
        <li {...stylex.props(styles.li)}>Điều hướng là một ngăn xếp với nút back bên trái; phím Escape về màn hình chính.</li>
        <li {...stylex.props(styles.li)}>Nhập liệu phải dùng được trên màn hình ngoài: ghi chú, tìm kiếm, nhắn tin, ở 387 điểm.</li>
        <li {...stylex.props(styles.li)}>Thời lượng chuyển động theo chuẩn iOS. Push mất cỡ 380 ms; không thứ gì nảy hai lần.</li>
        <li {...stylex.props(styles.li)}>
          Widget là ảnh chụp trạng thái mà shell vẽ ra, kèm thời điểm chụp. Nó không phải khung nhìn sống của app.
        </li>
      </ul>
      <p {...stylex.props(styles.p)}>
        Toàn bộ component:{' '}
        <Link to="/kit" {...stylex.props(styles.link)}>
          UI kit
        </Link>
        . Cơ chế nếp gấp:{' '}
        <Link to="/docs/$" params={{ _splat: 'displays' }} {...stylex.props(styles.link)}>
          Màn hình và nếp gấp
        </Link>
        .
      </p>
    </div>
  )
}

/** A numbered rule: mono number in its own column, the rule beside it. */
function Rule({ n, title, children }: { n: string; title: string; children: ReactNode }) {
  return (
    <li {...stylex.props(styles.rule)}>
      <span {...stylex.props(styles.n)} aria-hidden="true">
        {n.padStart(2, '0')}
      </span>
      <div {...stylex.props(styles.body)}>
        <h3 {...stylex.props(styles.ruleTitle)}>{title}</h3>
        {children}
      </div>
    </li>
  )
}

const styles = stylex.create({
  measure: { maxWidth: '760px' },
  rules: { listStyleType: 'none', margin: 0, padding: 0, display: 'grid', gap: '14px' },
  rule: {
    display: 'grid',
    gridTemplateColumns: { default: '44px minmax(0, 1fr)', [SMALL]: 'minmax(0, 1fr)' },
    gap: { default: '4px', [SMALL]: '10px' },
    backgroundColor: color.surface,
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: { default: color.border, ':hover': color.borderStrong },
    borderRadius: radius.md,
    paddingTop: '26px',
    paddingBottom: '12px',
    paddingLeft: { default: '28px', [SMALL]: '20px' },
    paddingRight: { default: '28px', [SMALL]: '20px' },
    transitionProperty: 'border-color, box-shadow, transform',
    transitionDuration: '0.25s',
    transitionTimingFunction: ease.out,
    transform: { default: 'translateY(0)', ':hover': 'translateY(-2px)' },
    boxShadow: { default: 'none', ':hover': color.shadow }
  },
  n: {
    display: 'block',
    marginTop: '4px',
    fontFamily: font.mono,
    fontSize: '12px',
    fontVariantNumeric: 'tabular-nums',
    letterSpacing: '0.12em',
    color: color.accent
  },
  body: { minWidth: 0 },
  ruleTitle: {
    margin: 0,
    marginBottom: '12px',
    fontFamily: font.display,
    fontSize: { default: '26px', [SMALL]: '22px' },
    lineHeight: 1.15,
    fontWeight: 600,
    letterSpacing: '-0.02em',
    color: color.text
  },
  h3: {
    fontFamily: font.mono,
    fontSize: '11px',
    fontWeight: 500,
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    color: color.text3,
    marginTop: '48px',
    marginBottom: '12px'
  },
  p: {
    fontFamily: font.sans,
    fontSize: '17px',
    lineHeight: 1.6,
    color: color.text,
    marginTop: 0,
    marginBottom: '16px'
  },
  ul: {
    fontFamily: font.sans,
    fontSize: '17px',
    lineHeight: 1.6,
    color: color.text,
    marginTop: 0,
    marginBottom: '24px',
    paddingLeft: '22px'
  },
  li: { marginBottom: '8px' },
  link: {
    color: { default: color.accent, ':hover': color.accentHover },
    textDecoration: { default: 'none', ':hover': 'underline' }
  }
})
