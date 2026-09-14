import type { ReactNode } from 'react'
import { WarningCircleIcon } from '@phosphor-icons/react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useI18n } from '@/i18n'
import { describeError } from '@/lib/describe-error'

export function ErrorAlert({ error, action }: { error: unknown; action?: ReactNode }) {
  const { t } = useI18n()
  return (
    <Alert
      variant="destructive"
      className="border-destructive/25 bg-destructive/[0.04] px-3 py-2.5 dark:bg-destructive/10"
    >
      <WarningCircleIcon weight="fill" />
      <AlertTitle className="leading-snug">{describeError(error, t)}</AlertTitle>
      {action && <AlertDescription className="mt-1.5">{action}</AlertDescription>}
    </Alert>
  )
}
