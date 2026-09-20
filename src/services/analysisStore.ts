import type { AnalysisResult } from '../types/analysis'

const analysisResults = new Map<string, AnalysisResult>()

export function storeAnalysisResult(result: AnalysisResult): void {
  analysisResults.set(result.incidentId, result)
}

export function getStoredAnalysisResult(incidentId: string): AnalysisResult | null {
  return analysisResults.get(incidentId) ?? null
}