import { createFileRoute } from '@tanstack/react-router'
import { KitHero } from '../kit/hero'

// One hero and nothing else: the kit in a sentence, running, with the door to
// the reference. Every export is documented under /kit/docs.
export const Route = createFileRoute('/kit/')({
  head: () => ({
    meta: [
      { title: 'UI kit · Duo' },
      {
        name: 'description',
        content:
          'Những component mà mọi app Duo được dựng nên từ đó: nút bấm, danh sách, điều hướng và widget sinh ra đã hiểu màn hình ngoài, màn hình trong và nếp gấp ở giữa.'
      }
    ]
  }),
  component: Index
})

function Index() {
  return <KitHero />
}
