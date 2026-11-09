package api

// A-04: ship a PPPC (Privacy Preferences Policy Control) configuration profile
// with the macOS agent so MDM admins can pre-approve Full Disk Access instead
// of clicking through System Settings on every Mac. The binary is not yet
// code-signed, so the profile identifies it by installed path; once a signed
// build exists the CodeRequirement should be switched to a bundle identifier.

import (
	"fmt"
	"html"
)

const macosAgentInstalledPath = "/usr/local/bin/obsidianwatch-agent"

func macosFDAProfile(payloadUUID, contentUUID string) string {
	p := html.EscapeString(macosAgentInstalledPath)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>io.obsidianwatch.agent.fda</string>
  <key>PayloadUUID</key><string>%s</string>
  <key>PayloadDisplayName</key><string>ObsidianWatch Agent - Full Disk Access</string>
  <key>PayloadOrganization</key><string>ObsidianWatch</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>io.obsidianwatch.agent.fda.tcc</string>
      <key>PayloadUUID</key><string>%s</string>
      <key>Services</key>
      <dict>
        <key>SystemPolicyAllFiles</key>
        <array>
          <dict>
            <key>Identifier</key><string>%s</string>
            <key>IdentifierType</key><string>path</string>
            <key>Allowed</key><true/>
            <key>Comment</key><string>ObsidianWatch agent: file monitoring and audit log access</string>
          </dict>
        </array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`, payloadUUID, contentUUID, p)
}
