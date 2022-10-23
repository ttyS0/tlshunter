package manifest

import "encoding/xml"

type Manifest struct {
	XMLName     xml.Name `xml:"manifest"`
	UsesSDK     UsesSDK
	Application Application
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
	XMLName        xml.Name `xml:"network-security-config"`
	BaseConfig     *BaseConfig
	DomainConfig   []*DomainConfig
	DebugOverrides *DebugOverrides
}

type BaseConfig struct {
	XMLName                   xml.Name `xml:"base-config"`
	CleartextTrafficPermitted *bool    `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors              *TrustAnchors
}

type DomainConfig struct {
	XMLName                   xml.Name `xml:"domain-config"`
	CleartextTrafficPermitted *bool    `xml:"cleartextTrafficPermitted,attr"`
	Domains                   []*Domain
	TrustAnchors              *TrustAnchors
	PinSet                    *PinSet
	Children                  []*DomainConfig
}

type Domain struct {
	IncludeSubdomains bool   `xml:"includeSubdomains,attr"`
	Data              string `xml:",innerxml"`
}

type DebugOverrides struct {
	XMLName      xml.Name `xml:"debug-overrides"`
	TrustAnchors *TrustAnchors
}

type TrustAnchors struct {
	XMLName xml.Name `xml:"trust-anchors"`

	Certificates []*Certificates
}

type Certificates struct {
	XMLName      xml.Name `xml:"certificates"`
	Src          string   `xml:"src,attr"`
	OverridePins *bool    `xml:"overridePins,attr"`
}

type PinSet struct {
	XMLName    xml.Name `xml:"pin-set"`
	Expiration string   `xml:"expiration"`
	Pins       []*Pin
}

type Pin struct {
	XMLName xml.Name `xml:"pin"`
	Digest  string   `xml:"digest,attr"`
	Data    string   `xml:",innerxml"`
}
