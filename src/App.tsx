import { useEffect, useState, type ComponentType } from 'react'
import { useRoute, type RouteId } from '@/app/routes'
import { AppShell } from '@/components/layout/app-shell'
import { PageContainer, PageHeader } from '@/components/common/page'
import { AesPage } from '@/features/aes/aes-page'
import { useI18n } from '@/i18n'
import { warmUpCrypto } from '@/lib/crypto/client'

function Placeholder({ title }: { title: string }) {
  return (
    <PageContainer>
      <PageHeader title={title} />
    </PageContainer>
  )
}

const PAGES: Record<RouteId, ComponentType> = {
  aes: AesPage,
  rsa: () => <Placeholder title="RSA" />,
  sign: () => <Placeholder title="Sign" />,
  keys: () => <Placeholder title="Keys" />,
  learn: () => <Placeholder title="Learn" />,
}

export default function App() {
  const route = useRoute()
  const { t } = useI18n()
  // Pages stay mounted once visited so switching tools never discards typed input.
  const [visited, setVisited] = useState<RouteId[]>([route])
  if (!visited.includes(route)) setVisited([...visited, route])

  useEffect(() => {
    warmUpCrypto()
  }, [])

  useEffect(() => {
    document.title = `${t(`nav.${route}`)} | ${t('app.name')}`
  }, [route, t])

  return (
    <AppShell>
      {visited.map((id) => {
        const Page = PAGES[id]
        return (
          <div key={id} hidden={id !== route} className="animate-in duration-300 fade-in">
            <Page />
          </div>
        )
      })}
    </AppShell>
  )
}
