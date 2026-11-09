package api

// sig_registry.go — every built-in signature set in one place (used by the
// sanity tests and the ATT&CK coverage view). Add new sets here.

func allSignatureSets() map[string][]ThreatSig {
	return map[string][]ThreatSig{
		// [NET-REGISTRY-BEGIN]
		// [NET-REGISTRY-END]
		// [APP-REGISTRY-BEGIN]
		// [APP-REGISTRY-END]
		"linux": linuxSignatures, "endpoint": endpointAgentSignatures, "dns": dnsCatSignatures,
		"windows": windowsSignatures, "windowsTamper": windowsTamperSignatures, "dc": dcSignatures,
		"macos": macosSignatures, "devops": devopsSignatures,
		"awsExt": cloudSignaturesExtended, "awsRecon": cloudReconSignatures, "cloudNet": cloudNetworkSignatures,
		"cloudLateral": cloudLateralSignatures, "cloudCompute": cloudComputeAbuseSignatures, "awsExtra": awsExtraSignatures,
		"gcpIAM": gcpIAMSignatures, "gcpCred": gcpCredentialSignatures, "gcpCompute": gcpComputeSignatures,
		"gcpData": gcpDataSignatures, "gcpNet": gcpNetworkSignatures, "gcpDefEv": gcpDefenseEvasionSignatures,
		"gcpPersist": gcpPersistenceSignatures, "gcpSCC": gcpSCCSignatures, "gcpTelemetry": gcpTelemetrySignatures,
		"gcpPolicy": gcpPolicySignatures, "gcpEsc": gcpEscalationSignatures,
		"azIAM": azureIAMSignatures, "azCompute": azureComputeSignatures, "azData": azureDataSignatures,
		"azNet": azureNetworkSignatures, "azDefEv": azureDefenseEvasionSignatures, "azDefender": azureDefenderSignatures,
		"azResource": azureResourceSignatures, "azAudit": azureAuditSignatures, "entra": entraIdentitySignatures,
		"winAccount": windowsAccountSignatures, "linAccount": linuxAccountSignatures, "remoteSession": remoteSessionSignatures,
		"gcpNew": gcpNewSignatures, "network": networkSignatures, "usb": usbSignatures, "software": softwareSignatures, "winUSB": windowsUSBSignatures,
	}
}
