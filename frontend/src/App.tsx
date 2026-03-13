import { useState, useCallback, useRef, DragEvent, ChangeEvent, useEffect } from 'react'
import './index.css'

// Types
type AnalysisType = 'infra' | 'todas_apps' | 'ot' | 'ad'
type RiskLevel = 'medium' | 'high' | 'critical'

interface FormState {
  tipo: AnalysisType
  minRisk: RiskLevel
  appName: string
  sheet: string
}

interface AppFiles {
  acuagis: File | null
  acuaprocess: File | null
  documento_equivalente: File | null
  acuacar_web: File | null
  acuaprocess_dev: File | null
}

interface ComparisonSummary {
  tipo: string
  min_risk: string
  total_nuevo: number
  total_nuevo_dedup: number
  total_historico: number
  total_historico_dedup: number
  nuevas: number
  persistentes: number
  reabiertas: number
  actualizadas: number
  mitigadas_desde_ultimo: number
  mitigadas_ausentes: number
  detecciones_criticas: number
  detecciones_altas: number
  detecciones_medias: number
  detalles?: {
    name: string
    host: string
    ip: string
    port: string
    description: string
    plugin_output: string
    risk: string
    status: string
    detection_date: string
    old_output?: string
    app_name?: string
  }[]
}

const APP_NAMES: { key: keyof AppFiles; label: string }[] = [
  { key: 'acuagis', label: 'Acuagis' },
  { key: 'acuaprocess', label: 'Acuaprocess' },
  { key: 'documento_equivalente', label: 'Documento Equivalente' },
  { key: 'acuacar_web', label: 'Acuacar web' },
  { key: 'acuaprocess_dev', label: 'Acuaprocess Dev' },
]

// Icons as SVG components
const UploadIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="17,8 12,3 7,8" />
    <line x1="12" y1="3" x2="12" y2="15" />
  </svg>
)

const FileIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14,2 L6,2 C4.9,2 4,2.9 4,4 L4,20 C4,21.1 4.9,22 6,22 L18,22 C19.1,22 20,21.1 20,20 L20,8 L14,2 Z" />
    <polyline points="14,2 14,8 20,8" />
  </svg>
)

const CheckIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
    <polyline points="22,4 12,14.01 9,11.01" />
  </svg>
)

const SettingsIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
)

const DownloadIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7,10 12,15 17,10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
)

const AlertIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
)

const CompareIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M16 3h5v5" />
    <line x1="21" y1="3" x2="14" y2="10" />
    <path d="M8 21H3v-5" />
    <line x1="3" y1="21" x2="10" y2="14" />
  </svg>
)

const AppsIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" />
  </svg>
)

const ChartIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10" />
    <line x1="12" y1="20" x2="12" y2="4" />
    <line x1="6" y1="20" x2="6" y2="14" />
  </svg>
)

// Animated counter hook
function useAnimatedCounter(target: number, duration: number = 1200): number {
  const [count, setCount] = useState(0)
  useEffect(() => {
    if (target === 0) { setCount(0); return }
    let start = 0
    const increment = target / (duration / 16)
    const timer = setInterval(() => {
      start += increment
      if (start >= target) {
        setCount(target)
        clearInterval(timer)
      } else {
        setCount(Math.floor(start))
      }
    }, 16)
    return () => clearInterval(timer)
  }, [target, duration])
  return count
}

// Stat Card Component
function StatCard({ label, value, color, delay }: { label: string; value: number; color: string; delay: number }) {
  const animated = useAnimatedCounter(value)
  return (
    <div className="stat-card" style={{ '--stat-color': color, animationDelay: `${delay}ms` } as React.CSSProperties}>
      <div className="stat-value">{animated.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
      <div className="stat-glow" />
    </div>
  )
}

// Donut Chart Component
function DonutChart({ data }: { data: { label: string; value: number; color: string }[] }) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null)
  const total = data.reduce((s, d) => s + d.value, 0)
  if (total === 0) return <div className="chart-empty">Sin datos</div>

  const radius = 80
  const strokeWidth = 24
  const center = 110
  const circumference = 2 * Math.PI * radius
  let offset = 0

  return (
    <div className="donut-chart-container">
      <svg viewBox="0 0 220 220" className="donut-chart">
        {/* Background ring */}
        <circle cx={center} cy={center} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={strokeWidth} />
        {data.map((item, i) => {
          const pct = item.value / total
          const dashLength = pct * circumference
          const currentOffset = offset
          offset += dashLength
          const isHovered = hoveredIdx === i
          return (
            <circle
              key={i}
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={item.color}
              strokeWidth={isHovered ? strokeWidth + 6 : strokeWidth}
              strokeDasharray={`${dashLength} ${circumference - dashLength}`}
              strokeDashoffset={-currentOffset}
              strokeLinecap="butt"
              className="donut-segment"
              style={{
                filter: isHovered ? `drop-shadow(0 0 8px ${item.color})` : 'none',
                transition: 'all 0.3s ease',
                animationDelay: `${i * 200 + 300}ms`
              }}
              onMouseEnter={() => setHoveredIdx(i)}
              onMouseLeave={() => setHoveredIdx(null)}
              transform={`rotate(-90 ${center} ${center})`}
            />
          )
        })}
        {/* Center text */}
        <text x={center} y={center - 8} textAnchor="middle" className="donut-total-value">{total}</text>
        <text x={center} y={center + 14} textAnchor="middle" className="donut-total-label">Total</text>
      </svg>
      <div className="donut-legend">
        {data.map((item, i) => (
          <div
            key={i}
            className={`legend-item ${hoveredIdx === i ? 'legend-active' : ''}`}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          >
            <span className="legend-dot" style={{ background: item.color }} />
            <span className="legend-label">{item.label}</span>
            <span className="legend-value">{item.value}</span>
            <span className="legend-pct">{(item.value / total * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Horizontal Bar Chart Component
function RiskBarChart({ data }: { data: { label: string; value: number; color: string; gradient: string }[] }) {
  const max = Math.max(...data.map(d => d.value), 1)
  return (
    <div className="bar-chart">
      {data.map((item, i) => (
        <div key={i} className="bar-row" style={{ animationDelay: `${i * 150 + 600}ms` }}>
          <div className="bar-label-row">
            <span className="bar-label">{item.label}</span>
            <span className="bar-value" style={{ color: item.color }}>{item.value}</span>
          </div>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{
                width: `${(item.value / max) * 100}%`,
                background: item.gradient,
                animationDelay: `${i * 150 + 800}ms`
              }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

// Search Icon
function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
    </svg>
  )
}

// Detailed Vulnerability Table Component
function VulnerabilityTable({ data, isAppsMode }: { data: NonNullable<ComparisonSummary['detalles']>; isAppsMode: boolean }) {
  const [page, setPage] = useState(0)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [searchVuln, setSearchVuln] = useState('')
  const [searchHost, setSearchHost] = useState('')
  const [searchIP, setSearchIP] = useState('')
  const [filterRisk, setFilterRisk] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterPort, setFilterPort] = useState('')
  const [filterApp, setFilterApp] = useState('')
  const [sortField, setSortField] = useState<string | null>(null)
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc')
  const rowsPerPage = 15

  if (!data || data.length === 0) return null

  // Faceted Search Logic: Options for each filter depend on other active filters
  const getFilteredForOptions = (excludeFilter: string) => {
    return data.filter(row => {
      const qV = searchVuln.toLowerCase()
      const qH = searchHost.toLowerCase()
      const qI = searchIP.toLowerCase()
      
      const matchesSearch = (!qV || row.name.toLowerCase().includes(qV)) &&
                           (!qH || row.host.toLowerCase().includes(qH)) &&
                           (!qI || row.ip.toLowerCase().includes(qI))
      
      const matchesRisk = excludeFilter === 'risk' || !filterRisk || row.risk.toLowerCase() === filterRisk.toLowerCase()
      const matchesStatus = excludeFilter === 'status' || !filterStatus || row.status.toLowerCase() === filterStatus.toLowerCase()
      const matchesPort = excludeFilter === 'port' || !filterPort || row.port === filterPort
      const matchesApp = excludeFilter === 'app' || !filterApp || row.app_name === filterApp
      
      return matchesSearch && matchesRisk && matchesStatus && matchesPort && matchesApp
    })
  }

  const uniqueRisks = Array.from(new Set(getFilteredForOptions('risk').map(d => d.risk).filter(Boolean))).sort()
  const uniqueStatuses = Array.from(new Set(getFilteredForOptions('status').map(d => d.status).filter(Boolean))).sort()
  const uniquePorts = Array.from(new Set(getFilteredForOptions('port').map(d => d.port).filter(p => p && p !== '0'))).sort((a, b) => Number(a) - Number(b))
  const uniqueApps = Array.from(new Set(getFilteredForOptions('app').map(d => d.app_name).filter(Boolean))).sort()

  // Apply filters
  const filteredData = data.filter(row => {
    const qV = searchVuln.toLowerCase()
    const qH = searchHost.toLowerCase()
    const qI = searchIP.toLowerCase()
    
    const matchesVuln = !qV || row.name.toLowerCase().includes(qV)
    const matchesHost = !qH || row.host.toLowerCase().includes(qH)
    const matchesIP = !qI || row.ip.toLowerCase().includes(qI)
    
    const matchesRisk = !filterRisk || row.risk.toLowerCase() === filterRisk.toLowerCase()
    const matchesStatus = !filterStatus || row.status.toLowerCase() === filterStatus.toLowerCase()
    const matchesPort = !filterPort || row.port === filterPort
    const matchesApp = !filterApp || row.app_name === filterApp
    
    return matchesVuln && matchesHost && matchesIP && matchesRisk && matchesStatus && matchesPort && matchesApp
  })

  // Apply sorting
  if (sortField) {
    filteredData.sort((a, b) => {
      let valA: any = a[sortField as keyof typeof a] || ''
      let valB: any = b[sortField as keyof typeof b] || ''
      
      // Numeric sort for port
      if (sortField === 'port') {
        const numA = parseInt(valA, 10) || 0
        const numB = parseInt(valB, 10) || 0
        return sortOrder === 'asc' ? numA - numB : numB - numA
      }
      
      // Case-insensitive string sort
      valA = valA.toString().toLowerCase()
      valB = valB.toString().toLowerCase()
      if (valA < valB) return sortOrder === 'asc' ? -1 : 1
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1
      return 0
    })
  }

  const totalPages = Math.ceil(filteredData.length / rowsPerPage)
  const safePage = Math.min(page, Math.max(totalPages - 1, 0))
  const displayData = filteredData.slice(safePage * rowsPerPage, (safePage + 1) * rowsPerPage)

  const hasActiveFilters = searchVuln || searchHost || searchIP || filterRisk || filterStatus || filterPort || filterApp

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('asc')
    }
  }

  const renderSortIcon = (field: string) => {
    if (sortField !== field) return <span className="sort-icon">↕</span>
    return <span className="sort-icon">{sortOrder === 'asc' ? '▲' : '▼'}</span>
  }

  const clearAllFilters = () => {
    setSearchVuln('')
    setSearchHost('')
    setSearchIP('')
    setFilterRisk('')
    setFilterStatus('')
    setFilterPort('')
    setFilterApp('')
    setSortField(null)
    setSortOrder('asc')
    setPage(0)
    setExpandedRow(null)
  }

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critico': return 'var(--accent-red)'
      case 'crítico': return 'var(--accent-red)'
      case 'alto': return 'var(--accent-orange)'
      case 'medio': return 'var(--accent-blue)'
      default: return 'var(--text-muted)'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'nuevas': return 'var(--accent-orange)'
      case 'persistentes': return 'var(--accent-blue)'
      case 'actualizadas': return 'var(--accent-purple)'
      case 'reabiertas': return 'var(--accent-red)'
      case 'mitigadas': return 'var(--accent-green)'
      default: return 'var(--text-muted)'
    }
  }

  const globalIdx = (localIdx: number) => safePage * rowsPerPage + localIdx

  return (
    <div className="table-container">
      <h3 className="chart-title">
        <span className="icon"><ChartIcon /></span>
        Detalle de Vulnerabilidades{hasActiveFilters ? ` — ${filteredData.length} de ${data.length}` : ` Obtenidas (${data.length})`}
      </h3>

      {/* Search and Filters Bar */}
      <div className="table-toolbar" style={{ flexDirection: 'column', gap: '1rem', alignItems: 'stretch' }}>
        <div className="table-search-group" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
          <div className="table-search">
            <span className="table-search-icon"><SearchIcon /></span>
            <input
              type="text"
              className="table-search-input"
              placeholder="Filtrar por Vulnerabilidad..."
              value={searchVuln}
              onChange={e => { setSearchVuln(e.target.value); setPage(0); setExpandedRow(null) }}
            />
          </div>
          <div className="table-search">
            <span className="table-search-icon"><SearchIcon /></span>
            <input
              type="text"
              className="table-search-input"
              placeholder="Filtrar por Host..."
              value={searchHost}
              onChange={e => { setSearchHost(e.target.value); setPage(0); setExpandedRow(null) }}
            />
          </div>
          <div className="table-search">
            <span className="table-search-icon"><SearchIcon /></span>
            <input
              type="text"
              className="table-search-input"
              placeholder="Filtrar por IP..."
              value={searchIP}
              onChange={e => { setSearchIP(e.target.value); setPage(0); setExpandedRow(null) }}
            />
          </div>
        </div>
        <div className="table-filters" style={{ justifyContent: 'flex-start' }}>
          {isAppsMode && uniqueApps.length > 0 && (
            <select
              className="table-filter-select"
              value={filterApp}
              onChange={e => { setFilterApp(e.target.value); setPage(0); setExpandedRow(null) }}
            >
              <option value="">Aplicación: Todas</option>
              {uniqueApps.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          )}
          <select
            className="table-filter-select"
            value={filterRisk}
            onChange={e => { setFilterRisk(e.target.value); setPage(0); setExpandedRow(null) }}
          >
            <option value="">Riesgo: Todos</option>
            {uniqueRisks.map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
          </select>
          <select
            className="table-filter-select"
            value={filterStatus}
            onChange={e => { setFilterStatus(e.target.value); setPage(0); setExpandedRow(null) }}
          >
            <option value="">Estado: Todos</option>
            {uniqueStatuses.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            className="table-filter-select"
            value={filterPort}
            onChange={e => { setFilterPort(e.target.value); setPage(0); setExpandedRow(null) }}
          >
            <option value="">Puerto: Todos</option>
            {uniquePorts.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          {hasActiveFilters && (
            <button className="table-filter-clear" onClick={clearAllFilters} title="Limpiar filtros">
              ✕
            </button>
          )}
        </div>
      </div>

      <div className="table-wrapper">
        <table className="vuln-table">
          <thead>
            <tr>
              {isAppsMode && <th onClick={() => handleSort('app_name')} className="clickable-header">Aplicación {renderSortIcon('app_name')}</th>}
              <th onClick={() => handleSort('name')} className="clickable-header">Vulnerabilidad {renderSortIcon('name')}</th>
              <th onClick={() => handleSort('host')} className="clickable-header">Host {renderSortIcon('host')}</th>
              <th onClick={() => handleSort('ip')} className="clickable-header">IP {renderSortIcon('ip')}</th>
              <th onClick={() => handleSort('port')} className="clickable-header">Puerto {renderSortIcon('port')}</th>
              <th onClick={() => handleSort('risk')} className="clickable-header text-center">Riesgo {renderSortIcon('risk')}</th>
              <th onClick={() => handleSort('status')} className="clickable-header text-center">Estado {renderSortIcon('status')}</th>
            </tr>
          </thead>
          <tbody>
            {displayData.length === 0 ? (
              <tr>
                <td colSpan={isAppsMode ? 7 : 6} className="table-empty-msg">No se encontraron resultados para los filtros aplicados.</td>
              </tr>
            ) : displayData.map((row, i) => {
              const gIdx = globalIdx(i)
              const isExpanded = expandedRow === gIdx
              return (
                <div key={gIdx} style={{ display: 'contents' }}>
                  <tr className={`vuln-row-clickable ${isExpanded ? 'vuln-row-expanded' : ''}`} onClick={() => setExpandedRow(isExpanded ? null : gIdx)}>
                    {isAppsMode && <td className="vuln-app" style={{ fontWeight: 500, color: 'var(--text-color)' }}>{row.app_name || '—'}</td>}
                    <td className="vuln-name">{row.name}</td>
                    <td className="vuln-host">{row.host || '—'}</td>
                    <td className="vuln-ip">{row.ip || '—'}</td>
                    <td className="vuln-port">{row.port || '—'}</td>
                    <td className="text-center">
                      <span className="badge-risk" style={{ borderColor: getRiskColor(row.risk), color: getRiskColor(row.risk) }}>
                        {row.risk || 'N/A'}
                      </span>
                    </td>
                    <td className="text-center">
                      <span className="badge-status" style={{ backgroundColor: `${getStatusColor(row.status)}20`, color: getStatusColor(row.status) }}>
                        {row.status}
                      </span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="vuln-desc-row">
                      <td colSpan={isAppsMode ? 7 : 6}>
                        <div className="vuln-desc-content">
                          {row.description && (
                            <div style={{ marginBottom: row.old_output ? '1.5rem' : '0' }}>
                              <strong>Descripción:</strong>
                              <p>{row.description}</p>
                            </div>
                          )}
                          
                          {row.old_output && (
                            <div className="output-diff">
                              <div className="output-box output-old">
                                <strong>Output Histórico:</strong>
                                <pre>{row.old_output}</pre>
                              </div>
                              <div className="output-box output-new">
                                <strong>Output Nuevo (Plugin Output):</strong>
                                <pre>{row.plugin_output}</pre>
                              </div>
                            </div>
                          )}
                          
                          {!row.old_output && row.plugin_output && (
                            <div style={{ marginTop: '1rem' }}>
                              <strong>Plugin Output:</strong>
                              <p>{row.plugin_output}</p>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </div>
              )
            })}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div className="pagination">
          <button className="btn btn-secondary btn-sm" disabled={safePage === 0} onClick={() => setPage(p => p - 1)}>
            Anterior
          </button>
          <span className="page-info">Página {safePage + 1} de {totalPages}</span>
          <button className="btn btn-secondary btn-sm" disabled={safePage === totalPages - 1} onClick={() => setPage(p => p + 1)}>
            Siguiente
          </button>
        </div>
      )}
    </div>
  )
}

// Results Dashboard Component
function ResultsDashboard({ summary, onDownload, onReset }: {
  summary: ComparisonSummary
  onDownload: () => void
  onReset: () => void
}) {
  const [globalAppFilter, setGlobalAppFilter] = useState('')

  const isAppsMode = summary.tipo === 'todas_apps'
  const allApps = isAppsMode && summary.detalles ? Array.from(new Set(summary.detalles.map(d => d.app_name).filter(Boolean))).sort() as string[] : []

  // Dynamic filter logic for standard arrays based on app filter
  let displayDetalles = summary.detalles || []
  let [nuevas, persistentes, actualizadas, reabiertas, mitigadas_desde_ultimo] = [
    summary.nuevas, summary.persistentes, summary.actualizadas, summary.reabiertas, summary.mitigadas_desde_ultimo
  ]
  let [criticas, altas, medias] = [
    summary.detecciones_criticas, summary.detecciones_altas, summary.detecciones_medias
  ]
  let totalDeduplicado = summary.total_nuevo_dedup
  let totalHistoricoDeduplicado = summary.total_historico_dedup

  if (isAppsMode && globalAppFilter && summary.detalles) {
    displayDetalles = summary.detalles.filter(d => d.app_name === globalAppFilter)
    
    // Recalcular métricas en base al array filtrado
    nuevas = displayDetalles.filter(d => d.status.toLowerCase() === 'nuevas').length
    persistentes = displayDetalles.filter(d => d.status.toLowerCase() === 'persistentes').length
    actualizadas = displayDetalles.filter(d => d.status.toLowerCase() === 'actualizadas').length
    reabiertas = displayDetalles.filter(d => d.status.toLowerCase() === 'reabiertas').length
    mitigadas_desde_ultimo = displayDetalles.filter(d => d.status.toLowerCase() === 'mitigadas').length
    
    const activeRiskItems = displayDetalles.filter(d => d.status.toLowerCase() !== 'mitigadas')
    criticas = activeRiskItems.filter(d => d.risk.toLowerCase() === 'critico' || d.risk.toLowerCase() === 'crítico').length
    altas = activeRiskItems.filter(d => d.risk.toLowerCase() === 'alto').length
    medias = activeRiskItems.filter(d => d.risk.toLowerCase() === 'medio').length

    totalDeduplicado = nuevas + persistentes + actualizadas + reabiertas
    totalHistoricoDeduplicado = 0 // Optional: hard to infer perfectly without original counts, hide or leave to 0. We'll leave it as a placeholder.
  }

  const classificationData = [
    { label: 'Nuevas', value: nuevas, color: '#f59e0b' },
    { label: 'Persistentes', value: persistentes, color: '#3b82f6' },
    { label: 'Actualizadas', value: actualizadas, color: '#8b5cf6' },
    { label: 'Reabiertas', value: reabiertas, color: '#ef4444' },
  ].filter(d => d.value > 0)

  const riskData = [
    {
      label: 'Críticas',
      value: criticas,
      color: '#ef4444',
      gradient: 'linear-gradient(90deg, #dc2626 0%, #f87171 100%)'
    },
    {
      label: 'Altas',
      value: altas,
      color: '#f59e0b',
      gradient: 'linear-gradient(90deg, #d97706 0%, #fbbf24 100%)'
    },
    {
      label: 'Medias',
      value: medias,
      color: '#3b82f6',
      gradient: 'linear-gradient(90deg, #2563eb 0%, #60a5fa 100%)'
    },
  ]

  const tipoLabel = summary.tipo === 'ot' ? 'Escaneo OT' : summary.tipo === 'infra' ? 'Infraestructura' : 'Aplicaciones'

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="dashboard-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="dashboard-header-content">
          <div className="dashboard-check"><CheckIcon /></div>
          <div>
            <h2 className="dashboard-title">Análisis Completado</h2>
            <p className="dashboard-subtitle">{tipoLabel} • Riesgo mínimo: {summary.min_risk}</p>
          </div>
        </div>

        {/* Resumen Selector Global por Aplicación */}
        {isAppsMode && allApps.length > 0 && (
          <div style={{ marginRight: '1rem' }}>
            <label style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginRight: '0.5rem' }}>Visualizando Aplicación:</label>
            <select
              className="table-filter-select"
              value={globalAppFilter}
              onChange={e => setGlobalAppFilter(e.target.value)}
              style={{ minWidth: '200px', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-color)', padding: '0.5rem', borderRadius: 'var(--radius-md)' }}
            >
              <option value="">Consolidado de todas las Apps</option>
              {allApps.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
        )}
      </div>

      {/* Stats Row */}
      <div className="stats-row">
        <StatCard label="Nuevas" value={nuevas} color="#f59e0b" delay={100} />
        <StatCard label="Persistentes" value={persistentes} color="#3b82f6" delay={200} />
        <StatCard label="Actualizadas" value={actualizadas} color="#8b5cf6" delay={300} />
        <StatCard label="Reabiertas" value={reabiertas} color="#ef4444" delay={400} />
        <StatCard label="Mitigadas" value={mitigadas_desde_ultimo} color="#10b981" delay={500} />
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        {/* Classification Donut */}
        <div className="chart-card">
          <h3 className="chart-title">
            <span className="icon"><ChartIcon /></span>
            Clasificación de Vulnerabilidades
          </h3>
          <DonutChart data={classificationData} />
        </div>

        {/* Risk Level Bars */}
        <div className="chart-card">
          <h3 className="chart-title">
            <span className="icon"><ChartIcon /></span>
            Detecciones por Nivel de Riesgo
          </h3>
          <RiskBarChart data={riskData} />
          <div className="chart-footer">
            <div className="chart-footer-item">
              <span className="chart-footer-label">Total escaneadas</span>
              <span className="chart-footer-value">{totalDeduplicado}</span>
            </div>
            {!globalAppFilter && (
              <div className="chart-footer-item">
                <span className="chart-footer-label">Historial</span>
                <span className="chart-footer-value">{totalHistoricoDeduplicado}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Vulnerability Details Table */}
      {displayDetalles.length > 0 && (
        <VulnerabilityTable data={displayDetalles} isAppsMode={isAppsMode} />
      )}

      {/* Actions */}
      <div className="dashboard-actions">
        <button className="btn btn-primary btn-download" onClick={onDownload}>
          <DownloadIcon /> Descargar Excel completo
        </button>
        <button className="btn btn-secondary" onClick={onReset}>
          <CompareIcon /> Nueva comparación
        </button>
      </div>
    </div>
  )
}

// File Upload Component
interface FileUploadProps {
  label: string
  accept: string
  file: File | null
  onFileSelect: (file: File | null) => void
  hint?: string
  compact?: boolean
}

function FileUpload({ label, accept, file, onFileSelect, hint, compact }: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault()
    setDragOver(false)
  }, [])

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) {
      onFileSelect(droppedFile)
    }
  }, [onFileSelect])

  const handleChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    onFileSelect(selectedFile || null)
  }, [onFileSelect])

  const handleClick = () => {
    inputRef.current?.click()
  }

  if (compact) {
    return (
      <div className="file-upload-compact">
        <label className="form-label">{label}</label>
        <div
          className={`file-upload-compact-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={handleClick}
        >
          {file ? (
            <span className="file-name-compact">{file.name}</span>
          ) : (
            <span className="file-placeholder">Seleccionar CSV...</span>
          )}
        </div>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={handleChange}
          style={{ display: 'none' }}
        />
      </div>
    )
  }

  return (
    <div className="form-group">
      <label className="form-label">{label}</label>
      <div
        className={`file-upload-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClick}
      >
        <div className="file-upload-icon">
          {file ? <FileIcon /> : <UploadIcon />}
        </div>
        <div className="file-upload-text">
          {file ? (
            <span className="file-name">
              <FileIcon /> {file.name}
            </span>
          ) : (
            <>
              Arrastra un archivo aquí o <span>selecciona</span>
              {hint && <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{hint}</div>}
            </>
          )}
        </div>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          onChange={handleChange}
          style={{ display: 'none' }}
        />
      </div>
    </div>
  )
}

// Main App Component
function App() {
  const [nuevoFile, setNuevoFile] = useState<File | null>(null)
  const [historicoFile, setHistoricoFile] = useState<File | null>(null)
  const [appFiles, setAppFiles] = useState<AppFiles>({
    acuagis: null,
    acuaprocess: null,
    documento_equivalente: null,
    acuacar_web: null,
    acuaprocess_dev: null,
  })
  const [form, setForm] = useState<FormState>({
    tipo: 'ot',
    minRisk: 'medium',
    appName: '',
    sheet: ''
  })
  const [multiAppStep, setMultiAppStep] = useState<1 | 2>(1)
  const [unifiedFile, setUnifiedFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [summary, setSummary] = useState<ComparisonSummary | null>(null)
  const [downloadBlob, setDownloadBlob] = useState<Blob | null>(null)

  const handleFormChange = (field: keyof FormState, value: string) => {
    setForm(prev => ({ ...prev, [field]: value }))
    setError(null)
  }

  const handleAppFileChange = (key: keyof AppFiles, file: File | null) => {
    setAppFiles(prev => ({ ...prev, [key]: file }))
    setError(null)
  }

  const hasAnyAppFile = Object.values(appFiles).some(f => f !== null)

  const canSubmit =
    ((form.tipo === 'infra' || form.tipo === 'ot' || form.tipo === 'ad') && nuevoFile && historicoFile) ||
    (form.tipo === 'todas_apps' && (
      (multiAppStep === 1 && hasAnyAppFile) ||
      (multiAppStep === 2 && unifiedFile && historicoFile)
    ))

  const handleDownloadExcel = useCallback(() => {
    if (!downloadBlob) return
    const url = window.URL.createObjectURL(downloadBlob)
    const a = document.createElement('a')
    a.href = url
    a.download = `resultado_comparacion_${form.tipo}.xlsx`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
  }, [downloadBlob, form.tipo])

  const handleSubmit = async () => {
    if (!canSubmit) return

    setLoading(true)
    setError(null)
    setSummary(null)
    setDownloadBlob(null)

    const formData = new FormData()

    if (form.tipo === 'todas_apps') {
      if (multiAppStep === 1) {
        // Paso 1: Unificar
        formData.append('min_risk', form.minRisk)
        if (appFiles.acuagis) formData.append('acuagis', appFiles.acuagis)
        if (appFiles.acuaprocess) formData.append('acuaprocess', appFiles.acuaprocess)
        if (appFiles.documento_equivalente) formData.append('documento_equivalente', appFiles.documento_equivalente)
        if (appFiles.acuacar_web) formData.append('acuacar_web', appFiles.acuacar_web)
        if (appFiles.acuaprocess_dev) formData.append('acuaprocess_dev', appFiles.acuaprocess_dev)

        try {
          const response = await fetch('/api/merge-apps', {
            method: 'POST',
            body: formData
          })

          if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Error en unificación' }))
            throw new Error(errorData.detail || `Error: ${response.status}`)
          }

          const blob = await response.blob()
          const file = new File([blob], 'escaneo_unificado.csv', { type: 'text/csv' })
          setUnifiedFile(file)
          setMultiAppStep(2)
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Error al unificar archivos')
        } finally {
          setLoading(false)
        }
      } else {
        // Paso 2: Comparar con histórico
        formData.append('unificado', unifiedFile!)
        formData.append('historico', historicoFile!)
        formData.append('min_risk', form.minRisk)
        if (form.sheet) formData.append('sheet', form.sheet)

        const formDataJson = new FormData()
        formDataJson.append('unificado', unifiedFile!)
        formDataJson.append('historico', historicoFile!)
        formDataJson.append('min_risk', form.minRisk)
        if (form.sheet) formDataJson.append('sheet', form.sheet)

        try {
          const [jsonRes, excelRes] = await Promise.all([
            fetch('/api/compare-unified-apps-json', {
              method: 'POST',
              body: formDataJson
            }),
            fetch('/api/compare-unified-apps', {
              method: 'POST',
              body: formData
            })
          ])

          if (!jsonRes.ok) {
            const contentType = jsonRes.headers.get("content-type")
            if (contentType && contentType.indexOf("application/json") !== -1) {
              const errorData = await jsonRes.json()
              throw new Error(errorData.detail || `Error: ${jsonRes.status}`)
            } else {
              const text = await jsonRes.text()
              if (text.includes("Proxy error") || text.includes("ECONNREFUSED")) {
                throw new Error("Error de conexión con el servidor (Proxy/Backend caído).")
              }
              throw new Error(`Error del servidor (${jsonRes.status}): ${text.slice(0, 100)}...`)
            }
          }

          const summaryData: ComparisonSummary = await jsonRes.json()
          setSummary(summaryData)

          if (excelRes.ok) {
            const blob = await excelRes.blob()
            setDownloadBlob(blob)
          }

        } catch (err) {
          setError(err instanceof Error ? err.message : 'Error en análisis comparativo')
        } finally {
          setLoading(false)
        }
      }
    } else {
      // Standard comparison (infra / ot): two parallel requests
      const formDataJson = new FormData()
      formDataJson.append('nuevo', nuevoFile!)
      formDataJson.append('historico', historicoFile!)
      formDataJson.append('tipo', form.tipo)
      formDataJson.append('min_risk', form.minRisk)
      if (form.sheet) formDataJson.append('sheet', form.sheet)

      formData.append('nuevo', nuevoFile!)
      formData.append('historico', historicoFile!)
      formData.append('tipo', form.tipo)
      formData.append('min_risk', form.minRisk)
      if (form.sheet) formData.append('sheet', form.sheet)

      try {
        // Fetch JSON summary and Excel in parallel
        const [jsonRes, excelRes] = await Promise.all([
          fetch('/api/compare-json', { method: 'POST', body: formDataJson }),
          fetch('/api/compare', { method: 'POST', body: formData }),
        ])

        if (!jsonRes.ok) {
          const contentType = jsonRes.headers.get("content-type")
          if (contentType && contentType.indexOf("application/json") !== -1) {
            const errorData = await jsonRes.json()
            throw new Error(errorData.detail || `Error: ${jsonRes.status}`)
          } else {
            const text = await jsonRes.text()
            if (text.includes("Proxy error") || text.includes("ECONNREFUSED")) {
              throw new Error("Error de conexión con el servidor (Proxy/Backend caído).")
            }
            throw new Error(`Error del servidor (${jsonRes.status}): ${text.slice(0, 100)}...`)
          }
        }

        const summaryData: ComparisonSummary = await jsonRes.json()
        setSummary(summaryData)

        if (excelRes.ok) {
          const blob = await excelRes.blob()
          setDownloadBlob(blob)
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Error al procesar la solicitud')
      } finally {
        setLoading(false)
      }
    }
  }

  const handleReset = () => {
    setNuevoFile(null)
    setHistoricoFile(null)
    setUnifiedFile(null)
    setMultiAppStep(1)
    setAppFiles({
      acuagis: null,
      acuaprocess: null,
      documento_equivalente: null,
      acuacar_web: null,
      acuaprocess_dev: null,
    })
    setSummary(null)
    setDownloadBlob(null)
    setError(null)
  }

  return (
    <>
      <div className="app-container">
        <header className="header">
          <h1>🔐 Comparador de Vulnerabilidades</h1>
          <p className="header-author">Autoría total de Nicolás Molina Díaz | Systems Engineer.</p>
          <p>Compara escaneos nuevos contra registros históricos</p>
        </header>

        {summary ? (
          <ResultsDashboard
            summary={summary}
            onDownload={handleDownloadExcel}
            onReset={handleReset}
          />
        ) : downloadBlob && !summary ? (
          /* Multi-app fallback: basic success screen */
          <div className="card result-success results">
            <div className="result-icon"><CheckIcon /></div>
            <h2 className="result-title">¡Comparación completada!</h2>
            <p className="result-subtitle">El archivo Excel se ha descargado automáticamente</p>
            <button className="btn btn-primary" onClick={handleReset}>
              <CompareIcon /> Nueva comparación
            </button>
          </div>
        ) : (
          <>
            {/* Configuration Card */}
            <div className="card">
              <h3 className="card-title">
                <span className="icon"><SettingsIcon /></span>
                Configuración
              </h3>

              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Tipo de análisis</label>
                  <select
                    className="form-select"
                    value={form.tipo}
                    onChange={(e) => {
                      handleFormChange('tipo', e.target.value as AnalysisType)
                      setMultiAppStep(1)
                      setUnifiedFile(null)
                    }}
                  >
                    <option value="infra">Infraestructura</option>
                    <option value="ad">Directorio Activo</option>
                    <option value="todas_apps">Aplicaciones</option>
                    <option value="ot">Escaneo OT</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Riesgo mínimo</label>
                  <select
                    className="form-select"
                    value={form.minRisk}
                    onChange={(e) => handleFormChange('minRisk', e.target.value)}
                  >
                    <option value="medium">Medium+</option>
                    <option value="high">High+</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>


              <div className="form-group">
                <label className="form-label">Hoja del Excel (opcional)</label>
                <input
                  type="text"
                  className="form-input"
                  value={form.sheet}
                  onChange={(e) => handleFormChange('sheet', e.target.value)}
                  placeholder="Nombre o índice (0, 1, 2...)"
                />
              </div>
            </div>

            {/* Files Card - Conditional based on tipo */}
            {form.tipo === 'todas_apps' ? (
              <>
                {multiAppStep === 1 ? (
                  /* Paso 1: Selección y Unificación */
                  <div className="card">
                    <h3 className="card-title">
                      <span className="icon"><AppsIcon /></span>
                      Paso 1: Normalización y Unificación
                    </h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
                      Sube el CSV de cada aplicación para asignarles su nombre correspondiente y unificarlos en un solo archivo.
                    </p>

                    <div className="apps-grid">
                      {APP_NAMES.map(({ key, label }) => (
                        <FileUpload
                          key={key}
                          label={label}
                          accept=".csv"
                          file={appFiles[key]}
                          onFileSelect={(f) => handleAppFileChange(key, f)}
                          compact
                        />
                      ))}
                    </div>
                  </div>
                ) : (
                  /* Paso 2: Histórico y Comparación */
                  <>
                    <div className="card alert-success" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--primary-color)' }}>
                      <h3 className="card-title">
                        <span className="icon"><CheckIcon /></span>
                        Paso 1 Completado
                      </h3>
                      <p style={{ marginBottom: '1rem' }}>Se han unificado los archivos de las aplicaciones.</p>
                      <div className="flex-row" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                        <div style={{ flex: 1, padding: '0.75rem', backgroundColor: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)', fontSize: '0.875rem' }}>
                          <FileIcon /> {unifiedFile?.name}
                        </div>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => {
                            const url = window.URL.createObjectURL(unifiedFile!)
                            const a = document.createElement('a')
                            a.href = url
                            a.download = unifiedFile!.name
                            a.click()
                            window.URL.revokeObjectURL(url)
                          }}
                        >
                          <DownloadIcon /> Descargar Unificado
                        </button>
                      </div>
                    </div>

                    <div className="card">
                      <h3 className="card-title">
                        <span className="icon"><FileIcon /></span>
                        Paso 2: Análisis Comparativo
                      </h3>
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
                        Selecciona el archivo histórico para proceder con la comparación.
                      </p>

                      <FileUpload
                        label="Archivo Histórico (Excel o CSV)"
                        accept=".xlsx,.xls,.csv"
                        file={historicoFile}
                        onFileSelect={setHistoricoFile}
                        hint="Debe contener columnas: Aplicación, Mitigado, Vulnerabilidad"
                      />
                    </div>
                  </>
                )}
              </>
            ) : (
              /* Standard file upload */
              <div className="card">
                <h3 className="card-title">
                  <span className="icon"><FileIcon /></span>
                  Archivos
                </h3>

                <FileUpload
                  label="Escaneo nuevo (CSV)"
                  accept=".csv"
                  file={nuevoFile}
                  onFileSelect={setNuevoFile}
                  hint="Archivo CSV con los resultados del escaneo reciente"
                />

                <FileUpload
                  label="Histórico (Excel o CSV)"
                  accept=".xlsx,.xls,.csv"
                  file={historicoFile}
                  onFileSelect={setHistoricoFile}
                  hint="Archivo histórico con columna 'Mitigado'"
                />
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="error-message">
                <span className="error-icon"><AlertIcon /></span>
                {error}
              </div>
            )}

            {/* Submit Button */}
            <button
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={!canSubmit || loading}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Procesando...
                </>
              ) : (
                <>
                  <DownloadIcon />
                  {form.tipo !== 'todas_apps'
                    ? 'Comparar y descargar'
                    : multiAppStep === 1
                      ? 'Normalizar y Unificar'
                      : 'Empezar análisis comparativo'
                  }
                </>
              )}
            </button>
          </>
        )}
      </div>

      <footer className="footer">
        <p>Comparador de Vulnerabilidades v1.2 • Sin almacenamiento de datos</p>
      </footer>
    </>
  )
}

export default App
