import type { DatasetFilter } from '../../../services/api'

export const WS3_DEMO_DATASET_ID = 'ws3-smoke-20260806-v2'

export type DatasetScope = 'all' | 'existing' | 'ws3'

export function datasetFilterForScope(scope: DatasetScope): DatasetFilter {
  if (scope === 'existing') return { exclude_dataset_id: WS3_DEMO_DATASET_ID }
  if (scope === 'ws3') return { dataset_id: WS3_DEMO_DATASET_ID }
  return {}
}

export interface DatasetFacet {
  dataset_id: string
  count: number
}

export interface DatasetFacets {
  datasets?: DatasetFacet[]
  unassigned?: number
  total?: number
}

export function datasetScopeCounts(facets: DatasetFacets | null) {
  const total = facets?.total ?? null
  const ws3 = facets?.datasets?.find(
    (facet) => facet.dataset_id === WS3_DEMO_DATASET_ID,
  )?.count ?? 0
  return {
    all: total,
    existing: total === null ? null : Math.max(0, total - ws3),
    ws3,
  }
}
