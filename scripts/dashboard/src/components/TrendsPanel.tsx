import { useMemo } from 'react'
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { TrendingUp, TrendingDown, Minus, BarChart3 } from 'lucide-react'
import { ScanMetadata, CommonFinding, TrendAnalysis } from '../types/findings'
import { computeTrendAnalysis } from '../utils/trendAnalysis'

interface TrendsPanelProps {
  scans: ScanMetadata[]
  allFindings: Map<string, CommonFinding[]>
}

/**
 * Trends panel with line and bar charts
 *
 * Features:
 * - Line chart: Findings over time (by severity)
 * - Bar chart: Top 10 rules
 * - Trend indicators (↑ increasing, ↓ decreasing, → stable)
 */
export default function TrendsPanel({ scans, allFindings }: TrendsPanelProps) {
  const trends: TrendAnalysis = useMemo(() => {
    return computeTrendAnalysis(scans, allFindings)
  }, [scans, allFindings])

  const getTrendIcon = () => {
    switch (trends.trend_direction) {
      case 'improving':
        return <TrendingDown className="w-5 h-5 text-green-600 dark:text-green-400" />
      case 'degrading':
        return <TrendingUp className="w-5 h-5 text-red-600 dark:text-red-400" />
      case 'stable':
        return <Minus className="w-5 h-5 text-gray-600 dark:text-gray-400" />
    }
  }

  const getTrendColor = () => {
    switch (trends.trend_direction) {
      case 'improving':
        return 'text-green-600 dark:text-green-400'
      case 'degrading':
        return 'text-red-600 dark:text-red-400'
      case 'stable':
        return 'text-gray-600 dark:text-gray-400'
    }
  }

  const getTrendText = () => {
    switch (trends.trend_direction) {
      case 'improving':
        return 'Improving'
      case 'degrading':
        return 'Degrading'
      case 'stable':
        return 'Stable'
    }
  }

  if (scans.length < 2) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        <div className="flex items-center gap-3 mb-4">
          <BarChart3 className="w-6 h-6 text-primary" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">
            Trend Analysis
          </h2>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400 italic">
          Need at least 2 scans to show trends. Keep scanning to build history!
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Trend Summary */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        <div className="flex items-center gap-3 mb-4">
          <BarChart3 className="w-6 h-6 text-primary" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">
            Trend Analysis
          </h2>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Trend Direction</p>
            <div className="flex items-center gap-2 mt-1">
              {getTrendIcon()}
              <p className={`text-xl font-bold ${getTrendColor()}`}>
                {getTrendText()}
              </p>
            </div>
          </div>

          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Total Change</p>
            <p
              className={`text-xl font-bold ${
                trends.total_change > 0
                  ? 'text-red-600 dark:text-red-400'
                  : trends.total_change < 0
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-gray-600 dark:text-gray-400'
              }`}
            >
              {trends.total_change > 0 ? '+' : ''}
              {trends.total_change}
            </p>
          </div>

          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Critical Change</p>
            <p
              className={`text-xl font-bold ${
                trends.critical_change > 0
                  ? 'text-red-600 dark:text-red-400'
                  : trends.critical_change < 0
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-gray-600 dark:text-gray-400'
              }`}
            >
              {trends.critical_change > 0 ? '+' : ''}
              {trends.critical_change}
            </p>
          </div>

          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Scans Analyzed</p>
            <p className="text-xl font-bold text-gray-900 dark:text-white">
              {scans.length}
            </p>
          </div>
        </div>
      </div>

      {/* Line Chart: Findings Over Time */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Findings Over Time
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={trends.data_points}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
            <XAxis
              dataKey="date"
              stroke="#9CA3AF"
              style={{ fontSize: '12px' }}
            />
            <YAxis stroke="#9CA3AF" style={{ fontSize: '12px' }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1F2937',
                border: '1px solid #374151',
                borderRadius: '6px',
                color: '#F3F4F6',
              }}
            />
            <Legend wrapperStyle={{ fontSize: '12px' }} />
            <Line
              type="monotone"
              dataKey="critical"
              stroke="#DC2626"
              strokeWidth={2}
              name="Critical"
              dot={{ r: 4 }}
            />
            <Line
              type="monotone"
              dataKey="high"
              stroke="#EA580C"
              strokeWidth={2}
              name="High"
              dot={{ r: 4 }}
            />
            <Line
              type="monotone"
              dataKey="medium"
              stroke="#D97706"
              strokeWidth={2}
              name="Medium"
              dot={{ r: 4 }}
            />
            <Line
              type="monotone"
              dataKey="low"
              stroke="#2563EB"
              strokeWidth={2}
              name="Low"
              dot={{ r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Bar Chart: Top 10 Rules */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Top 10 Most Frequent Rules
        </h3>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={trends.top_rules} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
            <XAxis type="number" stroke="#9CA3AF" style={{ fontSize: '12px' }} />
            <YAxis
              type="category"
              dataKey="rule_id"
              stroke="#9CA3AF"
              style={{ fontSize: '11px' }}
              width={120}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1F2937',
                border: '1px solid #374151',
                borderRadius: '6px',
                color: '#F3F4F6',
              }}
              formatter={(value: any, _name: string, props: any) => {
                const { severity, tool } = props.payload
                return [
                  <div key="tooltip">
                    <div>Count: {value}</div>
                    <div>Severity: {severity}</div>
                    <div>Tool: {tool}</div>
                  </div>,
                ]
              }}
            />
            <Bar
              dataKey="count"
              fill="#3B82F6"
              radius={[0, 4, 4, 0]}
              name="Occurrences"
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
