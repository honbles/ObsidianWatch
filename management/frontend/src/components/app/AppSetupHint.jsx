// What to do next for a service that has not reached the next tier (spec 11.6).
export default function AppSetupHint({ tier, name, environment }) {
  if (tier >= 2) return null
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
          <div><b>Instrument with OpenTelemetry</b> to unlock routes, dependencies, request statistics and the request-based detections. Host runtime detections already run without it.</div>
          <pre className="bg-black/30 rounded p-2 text-[11px] overflow-x-auto">{lines.join('\n')}</pre>
          <div className="text-sky-300/70">The host needs an agent built with the <b>app-server</b> profile. The receiver listens on loopback only; gRPC is not supported, use OTLP/HTTP.</div>
        </>
      ) : (
        <div><b>Add the security helper</b> to report authentication, authorization, input-rejection and data-export events. Those events lift this service to Tier 2 and unlock the detections that need them.</div>
      )}
    </div>
  )
}
