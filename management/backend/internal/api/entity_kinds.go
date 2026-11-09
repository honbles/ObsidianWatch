package api

// entity_kinds.go — closed registry of alert-entity kinds shared by both
// builds. Owned by the integration owner. A side adds its kinds only through
// the marked block below (additive).

const (
	EntityHost = "host" // agent hostname (existing agents)
	EntityUser = "user"
	EntityIP   = "ip"
	// [NET-ENTITY-BEGIN]
	EntityDevice   = "device"   // MAC (network probe)
	EntityObserver = "observer" // network device that produced the log
	EntitySite     = "site"     // probe site
	// [NET-ENTITY-END]
	// [APP-ENTITY-BEGIN]
	EntityService         = "service"          // "name|environment"
	EntityServiceInstance = "service_instance" // numeric instance id as text
	EntityRoute           = "route"            // "name|environment|METHOD /template"
	// [APP-ENTITY-END]
)
