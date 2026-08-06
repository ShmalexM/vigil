import { describe, expect, it } from 'vitest'
import {
  WS3_DEMO_DATASET_ID,
  datasetFilterForScope,
  datasetScopeCounts,
} from './datasetScope'

describe('dashboard dataset scope', () => {
  it('maps All, Existing, and WS3 to exact API filters', () => {
    expect(datasetFilterForScope('all')).toEqual({})
    expect(datasetFilterForScope('existing')).toEqual({
      exclude_dataset_id: WS3_DEMO_DATASET_ID,
    })
    expect(datasetFilterForScope('ws3')).toEqual({
      dataset_id: WS3_DEMO_DATASET_ID,
    })
  })

  it('derives selector counts from the dataset facet response', () => {
    expect(datasetScopeCounts({
      total: 61,
      unassigned: 25,
      datasets: [{ dataset_id: WS3_DEMO_DATASET_ID, count: 36 }],
    })).toEqual({ all: 61, existing: 25, ws3: 36 })
  })
})
