import { DesktopIcon, MoonIcon, SunIcon } from '@phosphor-icons/react'
import { Segmented } from '@/components/common/segmented'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n, type Lang } from '@/i18n'
import { updateSettings, useSettings, type Level } from '@/stores/settings'
import { setTheme, useTheme, type ThemePreference } from '@/stores/theme'

export function LevelSwitch({ className }: { className?: string }) {
  const { t } = useI18n()
  const { level } = useSettings()
  return (
    <div className={className}>
      <Segmented<Level>
        value={level}
        onValueChange={(next) => updateSettings({ level: next })}
        ariaLabel={t('settings.level')}
        fullWidth
        options={[
          { value: 'basic', label: t('settings.basic') },
          { value: 'advanced', label: t('settings.advanced') },
        ]}
      />
      <p className="mt-1.5 px-0.5 text-xs text-muted-foreground">
        {level === 'basic' ? t('settings.basicHint') : t('settings.advancedHint')}
      </p>
    </div>
  )
}

export function ThemeMenu() {
  const { t } = useI18n()
  const { preference } = useTheme()
  const ActiveIcon = preference === 'light' ? SunIcon : preference === 'dark' ? MoonIcon : DesktopIcon
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('settings.theme')}>
              <ActiveIcon className="size-4.5" />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>{t('settings.theme')}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="start" className="min-w-44">
        <DropdownMenuLabel>{t('settings.theme')}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={preference} onValueChange={(value) => setTheme(value as ThemePreference)}>
          <DropdownMenuRadioItem value="light">
            <SunIcon /> {t('settings.themeLight')}
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">
            <MoonIcon /> {t('settings.themeDark')}
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">
            <DesktopIcon /> {t('settings.themeSystem')}
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function LanguageSwitch() {
  const { t, lang } = useI18n()
  return (
    <Segmented<Lang>
      size="sm"
      value={lang}
      onValueChange={(next) => updateSettings({ lang: next })}
      ariaLabel={t('settings.language')}
      options={[
        { value: 'vi', label: 'VI' },
        { value: 'en', label: 'EN' },
      ]}
    />
  )
}
