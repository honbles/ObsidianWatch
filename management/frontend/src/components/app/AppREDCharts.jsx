import { ResponsiveContainer, AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts'
import { appMs } from './appFormat'

const fmtT = (iso, step) => {
  const d = new Date(iso)
  return step >= 86400 || step >= 21600 ? d.toLocaleDateString([], { month: 'short', day: 'numeric' })
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function Panel({ title, unit, children }) {
  return (
    <div className="ow-card" style={{ padding: '14px 16px', minWidth: 0 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontWeight: 500 }}>{title}</span><span className="mono t2" style={{ fontSize: 13.5 }}>{unit}</span>
      </div>
      <div style={{ height: 140 }}>{children}</div>
    </div>
  )
}

// Rate, error rate and latency with deploy markers overlaid (spec 11.3).
// series: API /red series; deploys: [{version, first_seen}]; step: seconds.
export default function AppREDCharts({ series, deploys = [], step = 60 }) {
  const data = series.map(p => ({
    t: new Date(p.t).getTime(), calls: p.calls, rpm: p.calls / (step / 60),
    err: p.calls ? (p.errors / p.calls) * 100 : 0, p50: p.p50_ms, p95: p.p95_ms, p99: p.p99_ms,
  }))
  const lo = data[0]?.t, hi = data[data.length - 1]?.t
  const marks = deploys.filter(d => { const t = new Date(d.first_seen).getTime(); return t >= lo && t <= hi })
  const axis = { stroke: 'var(--t3)', fontSize: 13, tickLine: false, axisLine: false }
  const x = <XAxis dataKey="t" type="number" scale="time" domain={['dataMin', 'dataMax']} tickFormatter={v => fmtT(v, step)} {...axis} />
  const grid = <CartesianGrid stroke="var(--line)" strokeDasharray="2 4" vertical={false} />
  const tip = (fmt) => (
    <Tooltip contentStyle={{ background: 'var(--s2)', border: '1px solid var(--line2)', borderRadius: 6, fontSize: 13.5, color: 'var(--t1)' }}
      labelFormatter={v => new Date(v).toLocaleString()} formatter={fmt} />
  )
  // label on the side with room: right of the line in the first 60% of the chart, left of it after
  const markers = marks.map(d => {
    const at = new Date(d.first_seen).getTime()
    const right = hi > lo && (at - lo) / (hi - lo) > 0.6
    return (
      <ReferenceLine key={d.version + d.first_seen} x={at} stroke="var(--line2)" strokeDasharray="3 3"
        label={{ value: `${d.version} deployed`, fill: 'var(--t2)', fontSize: 12, position: right ? 'insideTopRight' : 'insideTopLeft' }} />
    )
  })
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(358px, 1fr))', gap: 12 }}>
      <Panel title="Throughput" unit="req/min">
        <ResponsiveContainer><AreaChart data={data}>{grid}{x}<YAxis {...axis} width={34} />{tip(v => [Number(v).toFixed(1), 'req/min'])}
          <Area dataKey="rpm" stroke="var(--acc)" fill="var(--acc)" fillOpacity={0.08} strokeWidth={2} isAnimationActive={false} />{markers}</AreaChart></ResponsiveContainer>
      </Panel>
      <Panel title="Error rate" unit="% · 5xx and failed spans">
        <ResponsiveContainer><AreaChart data={data}>{grid}{x}<YAxis {...axis} width={34} tickFormatter={v => `${v}%`} />{tip(v => [`${Number(v).toFixed(2)}%`, 'errors'])}
          <Area dataKey="err" stroke="var(--crit)" fill="var(--crit)" fillOpacity={0.06} strokeWidth={2} isAnimationActive={false} />{markers}</AreaChart></ResponsiveContainer>
      </Panel>
      <Panel title="Latency" unit="p50 · p95 · p99">
        <ResponsiveContainer><LineChart data={data}>{grid}{x}<YAxis {...axis} width={52} tickFormatter={v => appMs(v).replace(' ', '')} />{tip((v, n) => [appMs(v), n])}
          <Line dataKey="p50" name="p50" stroke="var(--t3)" dot={false} strokeWidth={1.5} isAnimationActive={false} />
          <Line dataKey="p95" name="p95" stroke="var(--warn)" dot={false} strokeWidth={2} isAnimationActive={false} />
          <Line dataKey="p99" name="p99" stroke="var(--t2)" strokeDasharray="4 3" dot={false} strokeWidth={1.5} isAnimationActive={false} />{markers}</LineChart></ResponsiveContainer>
      </Panel>
    </div>
  )
}
