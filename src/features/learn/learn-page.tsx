import { useState, type ComponentType } from 'react'
import type { Icon } from '@phosphor-icons/react'
import { FunctionIcon, GridFourIcon, ImageSquareIcon } from '@phosphor-icons/react'
import { cn } from 'cn'
import { Tabs as TabsPrimitive } from 'radix-ui'
import { PageContainer, PageHeader } from '@/components/common/page'
import { usePersistentState } from '@/hooks/use-persistent-state'
import { useI18n, type TKey } from '@/i18n'
import { AesLesson } from './aes-lesson'
import { BlockModesLesson } from './block-modes-lesson'
import { RsaLesson } from './rsa-lesson'

type LessonId = 'modes' | 'aes' | 'rsa'

const LESSONS: ReadonlyArray<{ id: LessonId; icon: Icon; title: TKey; summary: TKey }> = [
  { id: 'modes', icon: ImageSquareIcon, title: 'learn.modes', summary: 'learn.modesSummary' },
  { id: 'aes', icon: GridFourIcon, title: 'learn.aes', summary: 'learn.aesSummary' },
  { id: 'rsa', icon: FunctionIcon, title: 'learn.rsa', summary: 'learn.rsaSummary' },
]

const isLessonId = (value: unknown): value is LessonId => LESSONS.some((lesson) => lesson.id === value)

const CONTENT: Record<LessonId, ComponentType> = {
  modes: BlockModesLesson,
  aes: AesLesson,
  rsa: RsaLesson,
}

export function LearnPage() {
  const { t } = useI18n()
  const [lesson, setLesson] = usePersistentState<LessonId>('edt.learn.lesson', 'modes', isLessonId)
  // Lessons stay mounted once opened, so switching back keeps their inputs and progress.
  const [visited, setVisited] = useState<LessonId[]>([lesson])
  if (!visited.includes(lesson)) setVisited([...visited, lesson])

  return (
    <PageContainer>
      <PageHeader title={t('learn.title')} description={t('learn.description')} />
      <TabsPrimitive.Root value={lesson} onValueChange={(value) => isLessonId(value) && setLesson(value)}>
        <TabsPrimitive.List
          aria-label={t('learn.lessons')}
          className="-mx-4 mb-6 grid snap-x scrollbar-thin auto-cols-[minmax(15rem,1fr)] grid-flow-col gap-3 overflow-x-auto px-4 pb-1 md:mx-0 md:grid-flow-row md:grid-cols-3 md:overflow-visible md:px-0 md:pb-0"
        >
          {LESSONS.map((item, index) => (
            <TabsPrimitive.Trigger
              key={item.id}
              value={item.id}
              className={cn(
                'group/lesson flex min-w-0 snap-start flex-col items-start gap-3 rounded-xl border bg-card p-4 text-left transition-[background-color,border-color,box-shadow] outline-none',
                'hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50',
                'data-[state=active]:border-primary/60 data-[state=active]:bg-primary/[0.05] data-[state=active]:shadow-[inset_0_0_0_1px_var(--primary)] dark:data-[state=active]:bg-primary/10',
              )}
            >
              <span className="flex w-full items-center justify-between gap-2">
                <span className="grid size-9 place-items-center rounded-lg bg-muted text-muted-foreground transition-colors group-data-[state=active]/lesson:bg-primary group-data-[state=active]/lesson:text-primary-foreground">
                  <item.icon weight="bold" className="size-[1.125rem]" />
                </span>
                <span className="text-xs font-medium text-muted-foreground tabular-nums">
                  {t('learn.lessonNumber', { number: index + 1 })}
                </span>
              </span>
              <span className="flex flex-col gap-1">
                <span className="text-[0.9375rem] leading-snug font-semibold">{t(item.title)}</span>
                <span className="text-xs leading-relaxed text-pretty text-muted-foreground">{t(item.summary)}</span>
              </span>
            </TabsPrimitive.Trigger>
          ))}
        </TabsPrimitive.List>
        {visited.map((id) => {
          const Lesson = CONTENT[id]
          return (
            <TabsPrimitive.Content
              key={id}
              value={id}
              forceMount
              hidden={id !== lesson}
              className="animate-in rounded-xl duration-300 outline-none fade-in focus-visible:ring-3 focus-visible:ring-ring/40 focus-visible:ring-offset-4 focus-visible:ring-offset-background"
            >
              <Lesson />
            </TabsPrimitive.Content>
          )
        })}
      </TabsPrimitive.Root>
    </PageContainer>
  )
}
