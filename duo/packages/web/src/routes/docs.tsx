import { createFileRoute, Outlet } from '@tanstack/react-router'
import { docs, groups } from '../docs'
import { SideLink, SideList, Split } from '../side-nav'

export const Route = createFileRoute('/docs')({ component: Layout })

function Layout() {
  return (
    <Split
      aside={
        <>
          {groups.map((g) => (
            <SideList key={g} title={g}>
              {docs
                .filter((d) => d.group === g)
                .map((d) => (
                  <SideLink key={d.slug} to="/docs/$" params={{ _splat: d.slug }}>
                    {d.title}
                  </SideLink>
                ))}
              {g === 'Xây dựng' && <SideLink to="/docs/sdk">Tham chiếu SDK</SideLink>}
            </SideList>
          ))}
          <SideList title="Tham chiếu">
            <SideLink to="/kit/docs">UI kit</SideLink>
            <SideLink to="/changelog">Lịch sử phiên bản</SideLink>
          </SideList>
        </>
      }
    >
      <Outlet />
    </Split>
  )
}
