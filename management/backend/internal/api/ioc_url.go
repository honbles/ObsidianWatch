package api

// URL indicators. Threat feeds publish full URLs, but the engine only matched
// IPs, domains and hashes, so every URL IOC was stored and never used.
//
// Two things are done with them:
//   - the exact URL is matched against URLs found in command lines
//   - the hostname is also registered as a domain IOC, unless the host is a
//     shared platform (github.com, pastebin.com ...) where blocking the whole
//     domain would alert on legitimate traffic. Those stay URL-only.
//
// URL entries share the domainIOCs map under the key "url:<normalised-url>"
// so matchIOC keeps its signature.

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"obsidianwatch/management/internal/store"
)

const urlIOCPrefix = "url:"

var urlInTextRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>\x60)\]]+`)

// sharedHostSkip lists hosts that serve both legitimate and malicious
// content. A URL on one of these never becomes a domain IOC; a subdomain of
// any entry is also skipped.
var sharedHostSkip = map[string]bool{
	"github.com": true, "githubusercontent.com": true, "gitlab.com": true, "bitbucket.org": true,
	"pastebin.com": true, "paste.ee": true, "hastebin.com": true, "ghostbin.com": true,
	"drive.google.com": true, "docs.google.com": true, "storage.googleapis.com": true,
	"googleusercontent.com": true, "dropbox.com": true, "dropboxusercontent.com": true,
	"onedrive.live.com": true, "sharepoint.com": true, "1drv.ms": true,
	"amazonaws.com": true, "cloudfront.net": true, "azurewebsites.net": true,
	"blob.core.windows.net": true, "windows.net": true, "herokuapp.com": true,
	"workers.dev": true, "pages.dev": true, "netlify.app": true, "vercel.app": true,
	"firebaseapp.com": true, "web.app": true, "discord.com": true, "discordapp.com": true,
	"cdn.discordapp.com": true, "telegram.org": true, "t.me": true, "bit.ly": true,
	"tinyurl.com": true, "cutt.ly": true, "mega.nz": true, "wetransfer.com": true,
	"ngrok.io": true, "ngrok-free.app": true, "trycloudflare.com": true,
	"raw.githack.com": true, "sourceforge.net": true, "wordpress.com": true,
	"blogspot.com": true, "weebly.com": true, "wixsite.com": true,
}

func isSharedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for h := host; h != ""; {
		if sharedHostSkip[h] {
			return true
		}
		i := strings.Index(h, ".")
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}

// normalizeURL lower-cases scheme and host, drops the fragment, default
// ports and a trailing slash. Returns "" if the input is not an http(s) URL.
func normalizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && !((u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443")) {
		host = net.JoinHostPort(host, p)
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	out := strings.ToLower(u.Scheme) + "://" + host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// urlHost returns the lower-cased hostname of a URL, or "".
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// addURLIOCs folds URL indicators into domainIOCs (see file comment). Existing
// domain IOCs are never overwritten. Returns the number of derived domains.
func addURLIOCs(domainIOCs map[string]store.IOCIndicator, urlIOCs map[string]store.IOCIndicator) int {
	derived := 0
	for _, ioc := range urlIOCs {
		n := normalizeURL(ioc.Value)
		if n == "" {
			continue
		}
		domainIOCs[urlIOCPrefix+n] = ioc
		host := urlHost(ioc.Value)
		if host == "" || net.ParseIP(host) != nil || isSharedHost(host) {
			continue
		}
		if _, exists := domainIOCs[host]; !exists {
			d := ioc
			d.IOCType = "domain"
			d.Value = host
			domainIOCs[host] = d
			derived++
		}
	}
	return derived
}

// matchURLIOC checks every URL found in text against the URL indicators.
func matchURLIOC(text string, domainIOCs map[string]store.IOCIndicator) *store.IOCIndicator {
	if text == "" {
		return nil
	}
	for _, m := range urlInTextRe.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:")
		if ioc, ok := domainIOCs[urlIOCPrefix+normalizeURL(m)]; ok {
			return &ioc
		}
	}
	return nil
}
