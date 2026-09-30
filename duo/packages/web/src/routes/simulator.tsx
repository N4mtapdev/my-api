import { createFileRoute } from '@tanstack/react-router'
import { Workspace } from '../builder/workspace'

/** `?app=` is a deep link: the home screen name (or catalog id) the phone opens on, from /apps. */
export const Route = createFileRoute('/simulator')({
  validateSearch: (search: Record<string, unknown>): { app?: string } => ({
    app: typeof search.app === 'string' && search.app ? search.app : undefined
  }),
  // Every other page separates with a middle dot; this one was the odd one out.
  head: () => ({
    meta: [
      { title: 'Simulator · Duo' },
      {
        name: 'description',
        content:
          'Chiếc máy nằm ngay trên trình duyệt: mở app, gập máy, xem màn hình trong và ngoài bàn giao phiên cho nhau.',
      }
    ]
  }),
  component: Page
})

function Page() {
  const { app } = Route.useSearch()
  return <Workspace upcoming app={app} />
}
