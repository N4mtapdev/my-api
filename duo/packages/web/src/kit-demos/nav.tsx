import { Button, Nav, Page, Row, Section, useNav } from '@doan-labs/duo-uikit'

function Root() {
  const nav = useNav()
  return (
    <Page title="Thư viện">
      <Section>
        <Row>
          <Button
            onClick={() =>
              nav.push((back) => (
                <Page title="Chi tiết" back={back}>
                  <Section>
                    <Row label="Pushed with" detail="useNav().push" />
                  </Section>
                </Page>
              ))
            }
          >
            Mở một trang
          </Button>
        </Row>
      </Section>
    </Page>
  )
}

export default function Demo() {
  return (
    <Nav>
      <Root />
    </Nav>
  )
}
