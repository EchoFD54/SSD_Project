export type SeverityLevel = 'Low' | 'Medium' | 'High' | 'Critical'

export type FindingStatus =
  | 'New'
  | 'Triaged'
  | 'InProgress'
  | 'Remediated'
  | 'AcceptedRisk'

export const SEVERITIES: SeverityLevel[] = ['Low', 'Medium', 'High', 'Critical']

export const STATUSES: FindingStatus[] = [
  'New',
  'Triaged',
  'InProgress',
  'Remediated',
  'AcceptedRisk',
]

export interface UserSession {
  isAuthenticated: boolean
  subject?: string
  username?: string
  email?: string
  roles?: string[]
}

export interface Finding {
  id: string
  title: string
  description: string
  affectedAsset: string
  severity: SeverityLevel
  discoveryDate: string
  status: FindingStatus
  reporterEmail: string | null
  assignedToUserId: string | null
  slaDueDate: string | null
}