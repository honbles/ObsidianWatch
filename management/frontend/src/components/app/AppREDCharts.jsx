import { ResponsiveContainer, AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts'
import { appMs } from './appFormat'

const fmtT = (iso, step) => {
  const d = new Date(iso)
  return step >= 86400 || step >= 21600 ? d.toLocaleDateString([], { month: 'short', day: 'numeric' })
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function Panel({ title, children }) {
  return (
    <div className="card p-3">
      <div className="text-[11px] text-siem-muted mb-1">{title}</div>
      <div style={{ height: 150 }}>{children}</div>
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
  const axis = { stroke: 'var(--text3)', fontSize: 10, tickLine: false, axisLine: false }
  const x = <XAxis dataKey="t" type="number" scale="time" domain={['dataMin', 'dataMax']} tickFormatter={v => fmtT(v, step)} {...axis} />
  const grid = <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
  const tip = (fmt) => (
    <Tooltip contentStyle={{ background: 'var(--surface2)', border: '1px solid var(--border)', fontSize: 11 }}
      labelFormatter={v => new Date(v).toLocaleString()} formatter={fmt} />
  )
  const markers = marks.map(d => (
    <ReferenceLine key={d.version + d.first_seen} x={new Date(d.first_seen).getTime()} stroke="var(--accent2)" strokeDasharray="4 3"
      label={{ value: d.version, fill: 'var(--accent2)', fontSize: 9, position: 'insideTopLeft' }} />
  ))
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <Panel title="Requests per minute">
        <ResponsiveContainer><AreaChart data={data}>{grid}{x}<YAxis {...axis} width={34} />{tip(v => [Number(v).toFixed(1), 'req/min'])}
          <Area dataKey="rpm" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.15} isAnimationActive={false} />{markers}</AreaChart></ResponsiveContainer>
      </Panel>
      <Panel title="Error rate (5xx and failed spans)">
        <ResponsiveContainer><AreaChart data={data}>{grid}{x}<YAxis {...axis} width={34} tickFormatter={v => `${v}%`} />{tip(v => [`${Number(v).toFixed(2)}%`, 'errors'])}
          <Area dataKey="err" stroke="var(--red)" fill="var(--red)" fillOpacity={0.15} isAnimationActive={false} />{markers}</AreaChart></ResponsiveContainer>
      </Panel>
      <Panel title="Latency (p50 / p95 / p99)">
        <ResponsiveContainer><LineChart data={data}>{grid}{x}<YAxis {...axis} width={40} tickFormatter={v => appMs(v)} />{tip(v => [appMs(v), ''])}
          <Line dataKey="p50" stroke="var(--green)" dot={false} strokeWidth={1.5} isAnimationActive={false} />
          <Line dataKey="p95" stroke="var(--yellow)" dot={false} strokeWidth={1.5} isAnimationActive={false} />
          <Line dataKey="p99" stroke="var(--orange)" dot={false} strokeWidth={1.5} isAnimationActive={false} />{markers}</LineChart></ResponsiveContainer>
      </Panel>
    </div>
  )
}
