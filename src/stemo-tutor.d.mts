export type TutorContext = Record<string, any>

export function summarizeDrawing(rawTrails: unknown): Record<string, any>
export function summarizeProgram(rawCommands: unknown): Record<string, any>
export function normalizeTutorContext(rawContext: unknown, curriculum: unknown): TutorContext
export function buildTutorMessages(
  message: string,
  context: TutorContext,
  eventType?: 'chat' | 'run_complete' | string,
): Array<{ role: string; content: string }>
export function createFallbackTutorResponse(
  context: TutorContext,
  eventType?: 'chat' | 'run_complete' | string,
): string
export function safeTutorResponse(rawResponse: unknown): string | null