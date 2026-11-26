// What to do next for a service that has not reached the next tier (spec 11.6).
export default function AppSetupHint({ tier, name, environment, instrumentation }) {
  if (tier >= 2) return null
  if (instrumentation === 'ebpf') {
    return (
      <div className="rounded-xl border border-sky-800/40 bg-sky-950/20 p-3 text-xs text-sky-200/90 space-y-1">
        <div><b>Traced with eBPF.</b> Add the OpenTelemetry SDK for exception details and runtime metrics, and the security helper for Tier 2.</div>
      </div>
    )
  }
  const env = environment && environment !== 'default' ? environment : '<environment>'
  const lines = [
    'OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318',
    'OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf',
    `OTEL_SERVICE_NAME=${name || '<service>'}`,
    `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=${env}`,
  ]
  return (
    <div className="rounded-xl border border-sky-800/40 bg-sky-950/20 p-3 text-xs text-sky-200/90 space-y-2">
      {tier === 0 ? (
        <>
          <div><b>Instrument with OpenTelemetry</b> for routes, dependencies and request detections.</div>
          <pre className="bg-black/30 rounded p-2 text-[11px] overflow-x-auto">{lines.join('\n')}</pre>
          <div className="text-sky-300/70">Needs an agent with the <b>app-server</b> profile. OTLP/HTTP on loopback only.</div>
        </>
      ) : (
        <div><b>Add the security helper</b> for Tier 2 (authentication, authorization, input and export events).</div>
      )}
    </div>
  )
}
