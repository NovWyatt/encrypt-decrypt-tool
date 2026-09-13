import { useEffect, useRef, useState } from 'react'
import { CheckIcon, CopyIcon } from '@phosphor-icons/react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/i18n'

interface CopyButtonProps {
  value: string
  label?: string
  iconOnly?: boolean
  variant?: 'outline' | 'ghost' | 'secondary' | 'default'
  size?: 'sm' | 'default' | 'xs' | 'icon-sm' | 'icon-xs' | 'icon'
  className?: string
  onCopied?: () => void
}

export function CopyButton({
  value,
  label,
  iconOnly,
  variant = 'outline',
  size = 'sm',
  className,
  onCopied,
}: CopyButtonProps) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => () => clearTimeout(timer.current), [])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      onCopied?.()
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 1600)
    } catch {
      toast.error(t('common.copyFailed'))
    }
  }

  const icon = copied ? <CheckIcon weight="bold" className="text-success" /> : <CopyIcon />
  const text = copied ? t('common.copied') : (label ?? t('common.copy'))

  if (iconOnly) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button type="button" variant={variant} size={size} onClick={copy} aria-label={text} className={className}>
            {icon}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{text}</TooltipContent>
      </Tooltip>
    )
  }
  return (
    <Button type="button" variant={variant} size={size} onClick={copy} className={className}>
      {icon}
      <span aria-live="polite">{text}</span>
    </Button>
  )
}
