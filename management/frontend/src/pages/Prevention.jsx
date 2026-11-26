import { PageHeader } from '../components/ui'
import PreventionSettings from './settings/Prevention'

// Endpoint prevention: the policy and the indicator set agents enforce.
export default function Prevention() {
  return (
    <div>
      <PageHeader title="Prevention"
        sub="Block known-malicious addresses, files and domains from threat intelligence."/>
      <div className="ow-body" style={{ maxWidth: 1100 }}>
        <PreventionSettings/>
      </div>
    </div>
  )
}
