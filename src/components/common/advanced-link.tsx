import { SlidersHorizontalIcon } from '@phosphor-icons/react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { updateSettings } from '@/stores/settings'

/** Switches the whole app to the advanced level, from places where basic hides an option. */
export function AdvancedLink() {
  const { t } = useI18n()
  return (
    <Button variant="link" size="sm" className="self-start px-0" onClick={() => updateSettings({ level: 'advanced' })}>
      <SlidersHorizontalIcon />
      {t('settings.advancedHint')}
    </Button>
  )
}
