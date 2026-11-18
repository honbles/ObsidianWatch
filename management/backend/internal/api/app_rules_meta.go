package api

// app_rules_meta.go - RuleMeta for the v1 Application Monitoring rules (spec 10.6/10.7).
// Owned by the Application build. Every rule starts in observe mode (shows as Info until promoted).
// IDs: APP-H## host runtime, APP-A## application, APP-X## cross-layer, APM-O## operational.

func appTun(key, label string, def float64, unit string) RuleTunable {
	return RuleTunable{Key: key, Label: label, Default: def, Unit: unit}
}

func init() {
	deploy := appTun("deploy_window_min", "Deploy window length", 30, "min")
	for _, m := range []RuleMeta{
		{ID: "APP-H01", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1505.003", "T1059"},
			WhatToCheck:    "Process tree and command line; whether the child connected out or wrote files; recent deploy.",
			FalsePositives: "Build scripts, health checks, scheduled jobs, PHP-style exec use.",
			Tunables:       []RuleTunable{appTun("followon_window_s", "Follow-on window (network or file write after the shell)", 300, "s")}},
		{ID: "APP-H02", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1105"},
			WhatToCheck:    "Command line and destination; whether the tool belongs to the app's normal job.",
			FalsePositives: "Deploy scripts, installers, image pulls."},
		{ID: "APP-H03", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1505.003"},
			WhatToCheck:    "Path, owner and file type; whether a deploy ran.",
			FalsePositives: "Deploys, legitimate script uploads into static directories.",
			Tunables:       []RuleTunable{deploy}},
		{ID: "APP-H04", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1071", "T1213"},
			WhatToCheck:    "Destination name, kind of dependency, who deployed.",
			FalsePositives: "New integrations, CDN or cloud address rotation.",
			Tunables:       []RuleTunable{appTun("min_days", "Learning days", 7, "days"), appTun("min_samples", "Minimum outbound connections learned", 200, "count"), deploy}},
		{ID: "APP-H05", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1071", "T1090"},
			WhatToCheck:    "Destination, whether a DNS lookup preceded it, intel source.",
			FalsePositives: "Internal services addressed by IP outside private ranges, some partner APIs."},
		{ID: "APP-H06", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1552.005"},
			WhatToCheck:    "Process, request path, cloud role in use.",
			FalsePositives: "Cloud SDK credential refresh.",
			Tunables:       []RuleTunable{appTun("min_days", "Learning days", 7, "days"), appTun("min_samples", "Minimum outbound connections learned", 200, "count")}},
		{ID: "APP-H07", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1552.001"},
			WhatToCheck:    "File, process and user; other reads in the minute before.",
			FalsePositives: "Backup agents, configuration tools, sshd and PAM."},
		{ID: "APP-H08", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1068"},
			WhatToCheck:    "Which change, parent process, related exec.",
			FalsePositives: "Services that gain or drop capabilities at start.",
			Tunables:       []RuleTunable{appTun("min_days", "Learning days", 7, "days")}},
		{ID: "APP-H11", Family: "app-h", Layer: "host", Tier: 0, ATTCK: []string{"T1611"},
			WhatToCheck:    "Process that touched the runtime socket or mounts; container image.",
			FalsePositives: "Container runtimes, orchestration agents, CI runners."},

		{ID: "APP-A01", Family: "app-a", Layer: "application", Tier: 1, ATTCK: []string{"T1110.004"},
			WhatToCheck:    "Client address, routes, volume, whether the service sits behind a proxy.",
			FalsePositives: "Shared NAT or corporate proxy, load tests.",
			Tunables:       []RuleTunable{appTun("threshold", "Failures per client address in the window", 20, "count"), appTun("window_min", "Window", 5, "min")}},
		{ID: "APP-A08", Family: "app-a", Layer: "application", Tier: 1,
			WhatToCheck:    "Route, method, first version seen, whether authentication is expected.",
			FalsePositives: "Normal feature releases.",
			Tunables:       []RuleTunable{appTun("min_days", "Learning days", 7, "days"), appTun("min_samples", "Minimum requests learned", 1000, "count"), deploy}},
		{ID: "APP-A09", Family: "app-a", Layer: "application", Tier: 1, ATTCK: []string{"T1190"},
			WhatToCheck:    "Route, exception types, client address, trace, follow-on process activity.",
			FalsePositives: "Authorized scanners, own security testing.",
			Tunables:       []RuleTunable{appTun("threshold", "Injection-class failures per client address and route", 3, "count"), appTun("window_min", "Window", 5, "min")}},
		{ID: "APP-A13", Family: "app-a", Layer: "application", Tier: 1, ATTCK: []string{"T1499.003"},
			WhatToCheck:    "Client address, route, 429 count.",
			FalsePositives: "Aggressive legitimate clients, batch jobs.",
			Tunables:       []RuleTunable{appTun("threshold", "429 responses per client address in the window", 50, "count"), appTun("window_min", "Window", 5, "min")}},

		{ID: "APP-X02", Family: "app-x", Layer: "cross", Tier: 1, ATTCK: []string{"T1190", "T1059"},
			WhatToCheck:    "The whole chain: request, exception, shell, outbound connection; process lineage.",
			FalsePositives: "Rare; test environments.",
			Tunables:       []RuleTunable{appTun("window_min", "Window between the application anomaly and the host execution", 15, "min"), appTun("spike_5xx", "5xx responses that count as a spike", 30, "count")}},
		{ID: "APP-X06", Family: "app-x", Layer: "cross", Tier: 1, ATTCK: []string{"T1562"},
			WhatToCheck:    "Whether the process restarted; configuration or environment change; deploy.",
			FalsePositives: "Intentional instrumentation changes.",
			Tunables:       []RuleTunable{appTun("grace_min", "Grace period without spans", 10, "min"), deploy}},

		{ID: "APM-O01", Family: "apm-o", Layer: "application", Tier: 1, Operational: true,
			WhatToCheck:    "Error rate against the service's error budget; recent deploy; failing dependency.",
			FalsePositives: "Planned maintenance, load tests.",
			Tunables:       []RuleTunable{appTun("min_calls", "Minimum requests in the window", 50, "count"), appTun("window_min", "Window", 10, "min"), appTun("default_budget_pct", "Error budget when the service has none", 5, "pct")}},
		{ID: "APM-O03", Family: "apm-o", Layer: "application", Tier: 1, Operational: true,
			WhatToCheck:    "Whether the service is up and reachable; upstream or network outage; possible denial of service.",
			FalsePositives: "Quiet periods, maintenance, holidays.",
			Tunables:       []RuleTunable{appTun("drop_pct", "Drop below baseline that counts", 80, "pct"), appTun("min_baseline", "Minimum baseline requests per window", 100, "count"), appTun("window_min", "Window", 10, "min")}},
		{ID: "APM-O05", Family: "apm-o", Layer: "application", Tier: 1, Operational: true,
			WhatToCheck:    "Whether the process or container is running; host health; restart history.",
			FalsePositives: "Scaling down, rolling restarts.",
			Tunables:       []RuleTunable{appTun("grace_min", "Time without reports before an instance is missing", 10, "min")}},
	} {
		m.DefaultObserve = true // every rule starts in observe mode
		RegisterRuleMeta(m)
	}
}
