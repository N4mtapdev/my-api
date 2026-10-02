import * as stylex from '@stylexjs/stylex'
import { createFileRoute, Link } from '@tanstack/react-router'
import { motion, useReducedMotion } from 'motion/react'
import { Button, Section } from '../layout'
import { CURVE } from '../motion'
import { Code, PageTop, Pre, SectionTop, Table, Td, Th, Tr } from '../page-parts'
import { blob, CATALOG, SUBMIT } from '../site'
import { color, ease, font, radius } from '../tokens.stylex'

// StyleX 0.19 cannot resolve an imported string as a media-query key, so the
// shared breakpoint is declared here (see tokens.stylex.ts).
const SMALL = '@media (max-width: 734px)'

export const Route = createFileRoute('/publish')({
  head: () => ({ meta: [{ title: 'Gửi app của bạn · Duo' }] }),
  component: Page
})

/** The submission guide, on its own URL because the nav, the footer and the apps page point here. */
function Page() {
  return (
    <Section narrow>
      <PageTop
        eyebrow="Đóng góp"
        title="Gửi app của bạn lên App Store của Duo"
        lead="Mọi đóng góp được review qua GitHub pull request."
      />
      <div {...stylex.props(styles.actions)}>
        <Button href={SUBMIT}>Gửi bằng GitHub</Button>
        <Button to="/get-started" outline>
          Viết app đầu tiên
        </Button>
      </div>
      <p {...stylex.props(styles.note)}>
        Nút bấm mở trang compare của GitHub với sẵn mẫu khai báo app - đó là tác dụng của{' '}
        <Code>?template=app-submission.md</Code> trong URL. Push nhánh chứa app của bạn lên trước; trang compare không
        tự tạo code giúp bạn.
      </p>
      <ol {...stylex.props(styles.timeline)}>
        <Step n={1} title="Chuẩn bị app">
          <p {...stylex.props(styles.p)}>
            Bạn cần Bun và một bản clone của repository. SDK, UI kit và CLI chưa lên npm, nên app được build dựa trên
            bản nén cục bộ:
          </p>
          <Pre lang="sh">{`bun install
bun scripts/package-platform.ts          # local SDK, kit and CLI archives, once
bun packages/cli/index.mjs create my-app --packages .cache/platform-packages/artifacts.json
cd my-app && bun install
bun run check                            # import boundaries, strict TypeScript, the 4 MiB cap`}</Pre>
          <p {...stylex.props(styles.p)}>
            Còn bỡ ngỡ?{' '}
            <Link to="/get-started" {...stylex.props(styles.link)}>
              Bắt đầu
            </Link>{' '}
            hướng dẫn lại các lệnh đó với simulator chạy song song.
          </p>
        </Step>
        <Step n={2} title="Kiểm tra yêu cầu">
          <p {...stylex.props(styles.p)}>Đây là các điều kiện cho đợt phát hành tuyển chọn đầu tiên. Tất cả đều được máy kiểm tra.</p>
          <Table>
            <thead>
              <tr>
                <Th>Quy tắc</Th>
                <Th>Nghĩa là gì</Th>
              </tr>
            </thead>
            <tbody>
              <Tr>
                <Td nowrap>Cả hai màn hình</Td>
                <Td>Chạy được trên màn hình trong lẫn màn hình ngoài khi gập. Hỗ trợ cover là bắt buộc, không tùy chọn.</Td>
              </Tr>
              <Tr>
                <Td nowrap>Chỉ dùng API công khai</Td>
                <Td>
                  Chỉ import từ <Code>@doan-labs/duo-sdk</Code> và <Code>@doan-labs/duo-uikit</Code>. Không import từ
                  shell, không import từ app khác.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Metadata đầy đủ</Td>
                <Td>
                  <Code>icon.png</Code> 1024 px, <Code>screenshots/inner.png</Code> và{' '}
                  <Code>screenshots/cover.png</Code>, <Code>README.md</Code> và <Code>CHANGELOG.md</Code>.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Giới hạn hiện hành</Td>
                <Td>
                  Tài liệu build ra phải nằm dưới trần 4 MiB mà <Code>check</Code> kiểm tra.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Lane</Td>
                <Td>
                  <Code>"lane": "community"</Code> trong manifest.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Không xin quyền</Td>
                <Td>
                  <Code>permissions</Code> để trống. App cần quyền thiết bị thì chưa đủ điều kiện ở thời điểm này.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Khai báo mạng</Td>
                <Td>
                  Mọi origin app kết nối tới phải nằm trong <Code>network</Code>. Ngoài danh sách đó, sandbox không với
                  tới gì khác.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>Giấy phép MIT</Td>
                <Td>
                  File <Code>LICENSE</Code> chứa nội dung MIT trong thư mục app.
                </Td>
              </Tr>
            </tbody>
          </Table>
        </Step>
        <Step n={3} title="Thêm mã nguồn">
          <p {...stylex.props(styles.p)}>
            App cộng đồng nằm trong repository dưới dạng mã nguồn. Fork repo, clone bản fork, rồi đặt app vào thư mục
            kebab-case riêng dưới <Code>community-apps/</Code>:
          </p>
          <Pre>{`community-apps/<app-slug>/`}</Pre>
          <p {...stylex.props(styles.p)}>
            Tên thư mục là để người đọc. Định danh thật là <Code>id</Code> dạng reverse-DNS trong manifest, và không bao
            giờ đổi sau khi phát hành.
          </p>
          <Table>
            <thead>
              <tr>
                <Th>File</Th>
                <Th>Là gì</Th>
              </tr>
            </thead>
            <tbody>
              <Tr>
                <Td nowrap>manifest.json</Td>
                <Td>Định danh, phiên bản, lane, quyền, các origin mạng đã khai báo.</Td>
              </Tr>
              <Tr>
                <Td nowrap>main.tsx</Td>
                <Td>Điểm khởi động, cùng mọi file nguồn khác nó import.</Td>
              </Tr>
              <Tr>
                <Td nowrap>package.json</Td>
                <Td>
                  Dependencies. Có <Code>bun.lock</Code> khi bạn thêm gì vượt ngoài bộ nền tảng:{' '}
                  <Code>@doan-labs/duo-sdk</Code>, <Code>@doan-labs/duo-uikit</Code>, <Code>@stylexjs/stylex</Code>,{' '}
                  <Code>react</Code>, <Code>react-dom</Code>.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>icon.png</Td>
                <Td>Hình vuông 1024 px.</Td>
              </Tr>
              <Tr>
                <Td nowrap>screenshots/</Td>
                <Td>
                  <Code>inner.png</Code> và <Code>cover.png</Code>, bắt buộc cả hai.
                </Td>
              </Tr>
              <Tr>
                <Td nowrap>README.md</Td>
                <Td>App làm gì và ứng xử thế nào qua nếp gấp.</Td>
              </Tr>
              <Tr>
                <Td nowrap>CHANGELOG.md</Td>
                <Td>Mỗi phiên bản một mục, mới nhất lên đầu.</Td>
              </Tr>
              <Tr>
                <Td nowrap>LICENSE</Td>
                <Td>MIT.</Td>
              </Tr>
            </tbody>
          </Table>
          <p {...stylex.props(styles.p)}>
            <a href={blob('community-apps/fold-compass')} {...stylex.props(styles.link)}>
              community-apps/fold-compass
            </a>{' '}
            là ví dụ hoàn chỉnh để học theo cấu trúc.
          </p>
          <p {...stylex.props(styles.p)}>
            Sau đó thêm mục của bạn vào{' '}
            <a href={blob('community-apps/registry.json')} {...stylex.props(styles.link)}>
              community-apps/registry.json
            </a>
            , file này ánh xạ mỗi app id tới thư mục của nó và tới các tài khoản GitHub được phép giữ mã nguồn. Đổi định
            danh, chuyển quyền sở hữu hay duyệt phát hành đều cần review từ đúng các tài khoản đó. Chuỗi{' '}
            <Code>author</Code> và <Code>repo</Code> trong manifest chỉ là nhãn, không phải bằng chứng sở hữu.
          </p>
          <p {...stylex.props(styles.p)}>Chạy đúng bước kiểm tra mà CI sẽ chạy, trước khi push:</p>
          <Pre lang="sh">{'bun scripts/check-submissions.ts community-apps/<app-slug>'}</Pre>
        </Step>
        <Step n={4} title="Mở pull request">
          <p {...stylex.props(styles.p)}>
            Commit lên một nhánh, push lên fork, rồi mở pull request vào <Code>main</Code> với mẫu{' '}
            <Code>app-submission</Code>. Mẫu này hỏi app id, phiên bản, thư mục, mục registry, dependency nào bạn thêm
            và vì sao, các origin mạng đã khai báo, và xác nhận đã chạy bước kiểm tra.
          </p>
          <p {...stylex.props(styles.p)}>
            Đính kèm cả hai ảnh chụp màn hình vào phần mô tả PR: màn hình trong và màn hình ngoài. Người review đọc
            manifest, diff, dependencies, origin đã khai báo, và cách app ứng xử khi máy bị gập lại trong lúc đang mở.
          </p>
        </Step>
        <Step n={5} title="Sau khi review">
          <p {...stylex.props(styles.p)}>Một bài gửi đi qua ba trạng thái, và chúng không phải là một:</p>
          <Table>
            <thead>
              <tr>
                <Th>Trạng thái</Th>
                <Th>Nghĩa là gì</Th>
              </tr>
            </thead>
            <tbody>
              <Tr>
                <Td nowrap>Check đạt</Td>
                <Td>Đủ điều kiện để được review. Chưa phải là được chấp nhận.</Td>
              </Tr>
              <Tr>
                <Td nowrap>Đã merge</Td>
                <Td>Được chấp nhận. Mã nguồn đã nằm trong repository.</Td>
              </Tr>
              <Tr>
                <Td nowrap>Đã phát hành</Td>
                <Td>
                  Workflow publish chạy thành công và bản phát hành đã nằm trong catalog tuyển chọn tại{' '}
                  <Code>{CATALOG}</Code>. Đến lúc đó app mới cài được.
                </Td>
              </Tr>
            </tbody>
          </Table>
          <p {...stylex.props(styles.p)}>
            Muốn phát hành bản cập nhật: tăng <Code>version</Code>, thêm mục changelog, và mở pull request mới. Nếu
            publish thất bại, lý do nằm ngay trong lần chạy workflow đó. Muốn rút app khỏi catalog, mở issue - việc gỡ
            chỉ chặn cài mới; app không bị gỡ khỏi máy ai và dữ liệu của họ không bị xóa.
          </p>
        </Step>
      </ol>
      <SectionTop
        eyebrow="Con đường khác"
        title="Tự host catalog của riêng bạn"
        lead="Bạn không cần catalog tuyển chọn để phát hành app. Cách này không đổi ở các lần sau."
      />
      <ol {...stylex.props(styles.plain)}>
        <li {...stylex.props(styles.item)}>
          <Code>bun run build</Code> trong app của bạn. <Code>dist/</Code> là một catalog hoàn chỉnh có một app.
        </li>
        <li {...stylex.props(styles.item)}>
          Đặt <Code>dist/</Code> lên bất kỳ host tĩnh nào phục vụ file với CORS và cache ngắn cho{' '}
          <Code>index.json</Code>.
        </li>
        <li {...stylex.props(styles.item)}>
          Chia sẻ URL của <Code>index.json</Code>. Ai đang chạy Duo dán nó vào ô Developer catalog trong App Store.
        </li>
      </ol>
      <p {...stylex.props(styles.p)}>
        Tăng version, tải thư mục phát hành mới lên, rồi thay <Code>index.json</Code> mới; đừng bao giờ sửa một thư mục
        phát hành đã công bố.{' '}
        <Link to="/docs/$" params={{ _splat: 'catalogs' }} {...stylex.props(styles.link)}>
          Catalog
        </Link>{' '}
        có định dạng và cách store dùng nó.
      </p>
    </Section>
  )
}

/** One step on the vertical timeline: a mono number sitting on the rule, then the body. */
function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  const still = useReducedMotion()
  return (
    // One step behind the next, so the timeline reads as a sequence. On mount
    // rather than on scroll, for the reason spelled out on `Reveal`.
    <motion.li
      {...stylex.props(styles.step)}
      initial={{ opacity: 0, transform: 'translateY(16px)' }}
      animate={{ opacity: 1, transform: 'translateY(0px)' }}
      transition={still ? { duration: 0 } : { duration: 0.5, delay: (n - 1) * 0.06, ease: CURVE }}
    >
      <span {...stylex.props(styles.n)} aria-hidden="true">
        {String(n).padStart(2, '0')}
      </span>
      <h2 {...stylex.props(styles.stepTitle)}>{title}</h2>
      {children}
    </motion.li>
  )
}

const styles = stylex.create({
  actions: { display: 'flex', flexWrap: 'wrap', gap: '12px', marginBottom: '20px' },
  note: {
    marginTop: 0,
    marginBottom: '40px',
    fontFamily: font.sans,
    fontSize: '15px',
    lineHeight: 1.6,
    color: color.text2
  },
  timeline: {
    listStyleType: 'none',
    margin: 0,
    marginTop: '8px',
    marginBottom: '48px',
    padding: 0,
    paddingLeft: '15px'
  },
  step: {
    position: 'relative',
    paddingLeft: { default: '40px', [SMALL]: '28px' },
    paddingBottom: '40px',
    borderLeftWidth: '1px',
    borderLeftStyle: 'solid',
    borderLeftColor: color.border
  },
  n: {
    position: 'absolute',
    left: '-16px',
    top: '-2px',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    borderRadius: radius.pill,
    backgroundColor: color.surface,
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: color.border,
    fontFamily: font.mono,
    fontSize: '12px',
    letterSpacing: '0.04em',
    color: color.accent
  },
  stepTitle: {
    margin: 0,
    marginBottom: '12px',
    fontFamily: font.display,
    fontSize: { default: '24px', [SMALL]: '21px' },
    lineHeight: 1.2,
    fontWeight: 600,
    letterSpacing: '-0.015em',
    color: color.text
  },
  p: {
    fontFamily: font.sans,
    fontSize: '17px',
    lineHeight: 1.6,
    color: color.text,
    marginTop: 0,
    marginBottom: '16px'
  },
  plain: {
    margin: 0,
    marginBottom: '16px',
    paddingLeft: '20px',
    fontFamily: font.sans,
    fontSize: '17px',
    lineHeight: 1.6,
    color: color.text
  },
  item: { marginBottom: '8px' },
  link: {
    color: { default: color.accent, ':hover': color.accentHover },
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
  }
})
