import * as Diff from 'diff'

export function computeTextDiff(original: string, modified: string) {
  const diff = Diff.diffWords(original, modified)
  return diff.map(part => ({
    type: part.added ? 'addition' : part.removed ? 'deletion' : 'unchanged',
    value: part.value,
    count: part.count || 0
  }))
}

export function calculateSimilarity(original: string, modified: string): number {
  if (!original && !modified) return 1
  if (!original || !modified) return 0
  
  const diff = Diff.diffWords(original, modified)
  const unchanged = diff.filter(d => !d.added && !d.removed)
    .reduce((sum, d) => sum + (d.value?.length || 0), 0)
  const total = Math.max(original.length, modified.length)
  
  return total > 0 ? unchanged / total : 1
}
