package manifest

import "encoding/xml"

type Manifest struct {
	XMLName     xml.Name    `xml:"manifest"`
	UsesSDK     UsesSDK     `xml:"uses-sdk"`
	Application Application `xml:"application"`
}

type UsesSDK struct {
	XMLName          xml.Name `xml:"uses-sdk"`
	MinSDKVersion    int      `xml:"minSdkVersion,attr"`
	TargetSDKVersion int      `xml:"targetSdkVersion,attr"`
}

type Application struct {
	XMLName               xml.Name `xml:"application"`
	Name                  string   `xml:"name,attr"`
	Label                 string   `xml:"label,attr"`
	NetworkSecurityConfig string   `xml:"networkSecurityConfig,attr"`
	UsesCleartextTraffic  *bool    `xml:"usesCleartextTraffic,attr"`
	Debuggable            *bool    `xml:"debuggable,attr"`
}

// Reference: https://developer.android.com/training/articles/security-config#FileFormat
type NetworkSecurityConfig struct {
	XMLName        xml.Name        `xml:"network-security-config"`
	BaseConfig     *BaseConfig     `xml:"base-config"`
	DomainConfig   []*DomainConfig `xml:"domain-config"`
	DebugOverrides *DebugOverrides `xml:"debug-overrides"`
}

type BaseConfig struct {
	XMLName                   xml.Name      `xml:"base-config"`
	CleartextTrafficPermitted *bool         `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors              *TrustAnchors `xml:"trust-anchors"`
}

type DomainConfig struct {
	XMLName                   xml.Name        `xml:"domain-config"`
	CleartextTrafficPermitted *bool           `xml:"cleartextTrafficPermitted,attr"`
	Domains                   []*Domain       `xml:"domain"`
	TrustAnchors              *TrustAnchors   `xml:"trust-anchors"`
	PinSet                    *PinSet         `xml:"pin-set"`
	Children                  []*DomainConfig `xml:"domain-config"`
}

type Domain struct {
	XMLName           xml.Name `xml:"domain"`
	IncludeSubdomains bool     `xml:"includeSubdomains,attr"`
	Data              string   `xml:",innerxml"`
}

type DebugOverrides struct {
	XMLName      xml.Name      `xml:"debug-overrides"`
	TrustAnchors *TrustAnchors `xml:"trust-anchors"`
}

type TrustAnchors struct {
	XMLName xml.Name `xml:"trust-anchors"`

	Certificates []*Certificates `xml:"certificates"`
}

type Certificates struct {
	XMLName      xml.Name `xml:"certificates"`
	Src          string   `xml:"src,attr"`
	OverridePins *bool    `xml:"overridePins,attr"`
}

type PinSet struct {
	XMLName    xml.Name `xml:"pin-set"`
	Expiration string   `xml:"expiration"`
	Pins       []*Pin   `xml:"pin"`
}

type Pin struct {
	XMLName xml.Name `xml:"pin"`
	Digest  string   `xml:"digest,attr"`
	Data    string   `xml:",innerxml"`
}
