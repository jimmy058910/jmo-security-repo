import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { CommonFinding } from '../types/findings'

interface SeverityChartProps {
  findings: CommonFinding[]
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626', // red-600
  HIGH: '#ea580c', // orange-600
  MEDIUM: '#f59e0b', // amber-500
  LOW: '#3b82f6', // blue-500
  INFO: '#6b7280' // gray-500
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function SeverityChart({ findings }: SeverityChartProps) {
  // Count findings by severity
  const severityCounts = SEVERITY_ORDER.map(severity => {
    const count = findings.filter(f => f.severity === severity).length
    return {
      severity,
      count,
      color: SEVERITY_COLORS[severity]
    }
  })

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg shadow-lg p-3">
          <p className="font-medium text-gray-900 dark:text-white">{data.severity}</p>
          <p className="text-sm text-gray-600 dark:text-gray-300">{data.count} findings</p>
        </div>
      )
    }
    return null
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 transition-colors">
      <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
        Severity Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={severityCounts} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
          <XAxis
            dataKey="severity"
            tick={{ fill: 'currentColor', fontSize: 11 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <YAxis
            tick={{ fill: 'currentColor', fontSize: 11 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0, 0, 0, 0.05)' }} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {severityCounts.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
