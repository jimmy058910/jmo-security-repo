import { useMemo } from 'react'
import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import { Shield } from 'lucide-react'
import { CommonFinding } from '../types/findings'

interface ComplianceRadarProps {
  findings: CommonFinding[]
}

interface ComplianceScore {
  framework: string
  fullName: string
  link: string
  coverage: number
  fullMark: 100
}

/**
 * Compliance radar chart
 *
 * Visualizes coverage across 6 compliance frameworks:
 * - OWASP Top 10 2021
 * - CWE Top 25 2024
 * - CIS Controls v8.1
 * - NIST CSF 2.0
 * - PCI DSS 4.0
 * - MITRE ATT&CK
 *
 * Coverage = (findings with framework mapping / total findings) * 100
 */
export default function ComplianceRadar({ findings }: ComplianceRadarProps) {
  const complianceData: ComplianceScore[] = useMemo(() => {
    if (findings.length === 0) {
      return [
        {
          framework: 'OWASP',
          fullName: 'OWASP Top 10 2021',
          link: 'https://owasp.org/www-project-top-ten/',
          coverage: 0,
          fullMark: 100,
        },
        {
          framework: 'CWE',
          fullName: 'CWE Top 25 2024',
          link: 'https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html',
          coverage: 0,
          fullMark: 100,
        },
        {
          framework: 'CIS',
          fullName: 'CIS Controls v8.1',
          link: 'https://www.cisecurity.org/controls/v8',
          coverage: 0,
          fullMark: 100,
        },
        {
          framework: 'NIST',
          fullName: 'NIST CSF 2.0',
          link: 'https://www.nist.gov/cyberframework',
          coverage: 0,
          fullMark: 100,
        },
        {
          framework: 'PCI DSS',
          fullName: 'PCI DSS 4.0',
          link: 'https://www.pcisecuritystandards.org/document_library/',
          coverage: 0,
          fullMark: 100,
        },
        {
          framework: 'ATT&CK',
          fullName: 'MITRE ATT&CK',
          link: 'https://attack.mitre.org/',
          coverage: 0,
          fullMark: 100,
        },
      ]
    }

    // Count findings with each framework mapping
    let owaspCount = 0
    let cweCount = 0
    let cisCount = 0
    let nistCount = 0
    let pciCount = 0
    let attackCount = 0

    findings.forEach(finding => {
      if (finding.compliance) {
        if (finding.compliance.owaspTop10_2021?.length) owaspCount++
        if (finding.compliance.cweTop25_2024?.length) cweCount++
        if (finding.compliance.cisControlsV8_1?.length) cisCount++
        if (finding.compliance.nistCsf2_0?.length) nistCount++
        if (finding.compliance.pciDss4_0?.length) pciCount++
        if (finding.compliance.mitreAttack?.length) attackCount++
      }
    })

    const total = findings.length

    return [
      {
        framework: 'OWASP',
        fullName: 'OWASP Top 10 2021',
        link: 'https://owasp.org/www-project-top-ten/',
        coverage: Math.round((owaspCount / total) * 100),
        fullMark: 100,
      },
      {
        framework: 'CWE',
        fullName: 'CWE Top 25 2024',
        link: 'https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html',
        coverage: Math.round((cweCount / total) * 100),
        fullMark: 100,
      },
      {
        framework: 'CIS',
        fullName: 'CIS Controls v8.1',
        link: 'https://www.cisecurity.org/controls/v8',
        coverage: Math.round((cisCount / total) * 100),
        fullMark: 100,
      },
      {
        framework: 'NIST',
        fullName: 'NIST CSF 2.0',
        link: 'https://www.nist.gov/cyberframework',
        coverage: Math.round((nistCount / total) * 100),
        fullMark: 100,
      },
      {
        framework: 'PCI DSS',
        fullName: 'PCI DSS 4.0',
        link: 'https://www.pcisecuritystandards.org/document_library/',
        coverage: Math.round((pciCount / total) * 100),
        fullMark: 100,
      },
      {
        framework: 'ATT&CK',
        fullName: 'MITRE ATT&CK',
        link: 'https://attack.mitre.org/',
        coverage: Math.round((attackCount / total) * 100),
        fullMark: 100,
      },
    ]
  }, [findings])

  const averageCoverage = useMemo(() => {
    const sum = complianceData.reduce((acc, item) => acc + item.coverage, 0)
    return Math.round(sum / complianceData.length)
  }, [complianceData])

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 80) return 'text-green-600 dark:text-green-400'
    if (coverage >= 60) return 'text-yellow-600 dark:text-yellow-400'
    if (coverage >= 40) return 'text-orange-600 dark:text-orange-400'
    return 'text-red-600 dark:text-red-400'
  }

  const getCoverageGrade = (coverage: number) => {
    if (coverage >= 90) return 'A'
    if (coverage >= 80) return 'B'
    if (coverage >= 70) return 'C'
    if (coverage >= 60) return 'D'
    return 'F'
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
      <div className="flex items-center gap-3 mb-4">
        <Shield className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">
          Compliance Framework Coverage
        </h2>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div>
          <p className="text-sm text-gray-600 dark:text-gray-400">Average Coverage</p>
          <p className={`text-3xl font-bold ${getCoverageColor(averageCoverage)}`}>
            {averageCoverage}%
          </p>
        </div>
        <div>
          <p className="text-sm text-gray-600 dark:text-gray-400">Coverage Grade</p>
          <p className={`text-3xl font-bold ${getCoverageColor(averageCoverage)}`}>
            {getCoverageGrade(averageCoverage)}
          </p>
        </div>
      </div>

      {/* Radar Chart */}
      <ResponsiveContainer width="100%" height={400}>
        <RadarChart data={complianceData}>
          <PolarGrid stroke="#374151" />
          <PolarAngleAxis
            dataKey="framework"
            stroke="#9CA3AF"
            style={{ fontSize: '12px' }}
          />
          <PolarRadiusAxis
            angle={90}
            domain={[0, 100]}
            stroke="#9CA3AF"
            style={{ fontSize: '10px' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1F2937',
              border: '1px solid #374151',
              borderRadius: '6px',
              color: '#F3F4F6',
            }}
            formatter={(value: any) => [`${value}%`, 'Coverage']}
          />
          <Radar
            name="Coverage"
            dataKey="coverage"
            stroke="#3B82F6"
            fill="#3B82F6"
            fillOpacity={0.6}
          />
        </RadarChart>
      </ResponsiveContainer>

      {/* Framework Breakdown */}
      <div className="mt-6 space-y-2">
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
          Framework Breakdown
        </h3>
        <div className="grid grid-cols-1 gap-3 text-sm">
          {complianceData.map(item => (
            <div
              key={item.framework}
              className="flex justify-between items-center p-3 rounded bg-gray-50 dark:bg-gray-700"
            >
              <div className="flex flex-col">
                <a
                  href={item.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline font-medium"
                  title={`Open ${item.fullName} documentation`}
                >
                  {item.fullName}
                </a>
                <span className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {item.framework}
                </span>
              </div>
              <span className={`font-bold text-lg ${getCoverageColor(item.coverage)}`}>
                {item.coverage}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-4 text-xs text-gray-500 dark:text-gray-400">
        <p>
          Coverage = (findings with framework mapping / total findings) × 100
        </p>
        <p className="mt-1">
          Higher coverage indicates better compliance mapping and regulatory alignment.
        </p>
      </div>
    </div>
  )
}
