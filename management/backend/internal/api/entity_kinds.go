package api

// entity_kinds.go — closed registry of alert-entity kinds shared by both
// builds. Owned by the integration owner. A side adds its kinds only through
// the marked block below (additive).

const (
	EntityHost = "host" // agent hostname (existing agents)
	EntityUser = "user"
	EntityIP   = "ip"
	// [GRAPH-ENTITY-BEGIN]
	EntityProcess  = "process" // "agent|guid" or "agent|pid:N|name" when no GUID
	EntityLogon    = "logon"   // "agent|0xLOGONID"
	EntityFile     = "file"    // "host|path"
	EntityRegistry = "reg"     // "host|key"
	EntityDomain   = "domain"  // lowercase DNS name
	// [GRAPH-ENTITY-END]
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
