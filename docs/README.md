# ObsidianWatch documentation

Four areas, one folder each. Every folder has a deployment guide, configuration pages and capability pages. Application and cloud split configuration and capability by framework or provider.

| Area | Deployment | Configuration | Capability (what it does, end to end) |
|---|---|---|---|
| [Endpoint](endpoint/) | [deployment.md](endpoint/deployment.md) | [configuration.md](endpoint/configuration.md) | [capability.md](endpoint/capability.md) |
| [Application (APM)](application/) | [deployment.md](application/deployment.md) | [platform](application/configuration-platform.md), [Java](application/configuration-java.md), [.NET](application/configuration-dotnet.md), [Python](application/configuration-python.md), [Node](application/configuration-node.md), [Go](application/configuration-go.md), [other SDKs](application/configuration-other-sdks.md) | [capability.md](application/capability.md) |
| [Cloud](cloud/) | [deployment.md](cloud/deployment.md) | [AWS](cloud/configuration-aws.md), [Azure](cloud/configuration-azure.md), [GCP](cloud/configuration-gcp.md) | [shared](cloud/capability.md), [AWS](cloud/capability-aws.md), [Azure](cloud/capability-azure.md), [GCP](cloud/capability-gcp.md) |
| [Codebase](codebase/) | [deployment.md](codebase/deployment.md) | [configuration.md](codebase/configuration.md) | [capability.md](codebase/capability.md) |

Also:

- [endpoint/identity.md](endpoint/identity.md): agent certificates, enrollment and the tunnel identity.
- [endpoint/response-actions.md](endpoint/response-actions.md): response action design and safety rules.
- [endpoint/prevention.md](endpoint/prevention.md): IP, hash and domain prevention from threat intelligence (audit and enforce).
- [application/node-security-guide.md](application/node-security-guide.md): the long Node.js walkthrough with helper files.
- [cloud/gcp/main.tf](cloud/gcp/main.tf): Terraform for the read-only GCP collector account.
- [development/](development/): UI design language and the device-management design notes.
- [known-issues.md](known-issues.md): defects found while writing these docs, not yet fixed.

The docs describe the code as it is. Where something has not been run against a real account, cluster or host, the page says so.
