package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/avast/apkparser"
	"github.com/sigeryang/droid-tlshunter/internal/manifest"
)

func ParseAPK(file string) (*manifest.Manifest, *apkparser.ZipReader, error) {
	zip, err := apkparser.OpenZip(file)

	if err != nil {
		return nil, nil, fmt.Errorf(`open zip error: %v`, err)
	}

	buf := new(bytes.Buffer)
	encoder := xml.NewEncoder(buf)
	rErr, mErr := apkparser.ParseApkWithZip(zip, encoder)

	if mErr != nil {
		return nil, nil, fmt.Errorf(`parse manifest error: %v`, mErr)
	}

	if rErr != nil {
		return nil, nil, fmt.Errorf(`parse resources error: %v`, rErr)
	}

	m := manifest.Manifest{}
	if err := xml.Unmarshal(buf.Bytes(), &m); err != nil {
		log.Printf(`unmarshal manifest error: %v`, err)
	}

	return &m, zip, nil
}

func SDKVersionToAndroidMajor(sdkVersion int) int {
	switch sdkVersion {
	case 1, 2, 3, 4:
		return 1
	case 5, 6, 7, 8, 9, 10:
		return 2
	case 11, 12, 13:
		return 3
	case 14, 15, 16, 17, 18, 19, 20:
		return 4
	case 21, 22:
		return 5
	case 23:
		return 6
	case 24, 25:
		return 7
	case 26, 27:
		return 8
	case 28:
		return 9
	case 29:
		return 10
	case 30:
		return 11
	case 31, 32:
		return 12
	case 33:
		return 13
	default:
		return 13
	}
}

type AndroidDefaults struct {
	AllowCleartext bool
	NSCPresence    bool
}

type Analysis struct {
	File          string `json:"file"`
	Name          string `json:"name"`
	TargetVersion int    `json:"target_version"`
	Risks         []Risk `json:"risks"`

	defaults AndroidDefaults
	m        *manifest.Manifest
	nsc      *manifest.NetworkSecurityConfig
}

type Risk struct {
	Type   RiskType `json:"type"`
	Reason string   `json:"reason"`
}

func (r Risk) String() string {
	return fmt.Sprintf("Type: %v Reason: %s", r.Type, r.Reason)
}

type RiskType int

//go:generate go run golang.org/x/tools/cmd/stringer -type=RiskType
const (
	RiskNSCMissing RiskType = iota
	RiskCleartext
	RiskUserAnchors
	RiskUnpinned
	RiskPinningExpiration
)

func (t RiskType) Description() string {
	switch t {
	case RiskNSCMissing:
		return "Android network security configuration is missing."
	case RiskCleartext:
		return "Allow cleartext traffic to be transferred."
	case RiskUserAnchors:
		return "Allow users to trust 3rd-party CAs."
	case RiskUnpinned:
		return "Does not pin any certificates."
	case RiskPinningExpiration:
		return "A pin set is about to expire / was already expired."
	default:
		return "(unknown)"
	}
}

func (a *Analysis) check() (ret []Risk) {
	ret = make([]Risk, 0)

	app := a.m.Application
	nsc := a.nsc
	defaults := a.defaults

	if nsc != nil {
		section := "NSC"
		{
			section := fmt.Sprintf("%s base config", section)
			baseConfig := nsc.BaseConfig
			if baseConfig == nil || baseConfig.CleartextTrafficPermitted == nil {
				if defaults.AllowCleartext {
					ret = append(ret, Risk{
						Type:   RiskCleartext,
						Reason: fmt.Sprintf("%s defaults permit cleartext traffic.", section),
					})
				}
			} else {
				if *baseConfig.CleartextTrafficPermitted {
					ret = append(ret, Risk{
						Type:   RiskCleartext,
						Reason: fmt.Sprintf("%s permit cleartext traffic.", section),
					})
				}
				anchors := baseConfig.TrustAnchors
				if anchors != nil {
					for i, certs := range anchors.Certificates {
						section := fmt.Sprintf("%s trust anchors (index: %d)", section, i)
						if certs.Src == "user" {
							ret = append(ret, Risk{
								Type:   RiskUserAnchors,
								Reason: fmt.Sprintf("%s allow user CAs.", section),
							})
						}

						// OverridePins is false by default under base config
						if certs.OverridePins != nil && *certs.OverridePins {
							ret = append(ret, Risk{
								Type:   RiskUserAnchors,
								Reason: fmt.Sprintf("%s override certificate pinning.", section),
							})
						}
					}
				}
			}
		}
		{
			section := fmt.Sprintf("%s domain config", section)
			domainConfig := nsc.DomainConfig
			var flattenDomainConfig func([]*manifest.DomainConfig) []*manifest.DomainConfig
			flattenDomainConfig = func(domainConfigs []*manifest.DomainConfig) (ret []*manifest.DomainConfig) {
				for _, domainConfig := range domainConfigs {
					if domainConfig != nil {
						ret = append(ret, domainConfig)
					}
					ret = append(ret, flattenDomainConfig(domainConfig.Children)...)
				}
				return
			}

			pinned := false
			domainConfigs := flattenDomainConfig(domainConfig)
			for i, domainConfig := range domainConfigs {
				section := fmt.Sprintf("%s sub config (index: %d)", section, i)
				if domainConfig.PinSet != nil {
					expiration, err := time.Parse("2006-01-02", domainConfig.PinSet.Expiration)
					if err != nil || time.Until(expiration).Hours() <= 10*24 {
						// (to be) expired within 10 days
						ret = append(ret, Risk{
							Type:   RiskPinningExpiration,
							Reason: fmt.Sprintf("%s pin set (will) hit its expiration.", section),
						})
					}

					if len(domainConfig.PinSet.Pins) > 0 {
						pinned = true
					}
				}
			}

			if !pinned {
				ret = append(ret, Risk{
					Type:   RiskUserAnchors,
					Reason: fmt.Sprintf("%s does not contain pinned certificates.", section),
				})
			}
		}
	} else {
		section := "Manifest"
		if defaults.NSCPresence {
			ret = append(ret, Risk{
				Type:   RiskNSCMissing,
				Reason: fmt.Sprintf("%s does not specify NSC where target Android version supports it.", section),
			})
		}

		if app.UsesCleartextTraffic == nil {
			if defaults.AllowCleartext {
				ret = append(ret, Risk{
					Type:   RiskCleartext,
					Reason: fmt.Sprintf("%s defaults permit cleartext traffic.", section),
				})
			}
		} else if *app.UsesCleartextTraffic {
			ret = append(ret, Risk{
				Type:   RiskCleartext,
				Reason: fmt.Sprintf("%s permit cleartext traffic.", section),
			})
		}
	}

	return
}

func (a *Analysis) String() string {
	risks := []string{}
	for i, risk := range a.Risks {
		risks = append(risks, fmt.Sprintf("    %d. %s", i+1, risk.String()))
	}
	return strings.TrimPrefix(fmt.Sprintf(`
File    : %s
Name    : %s
Version : Android %d (target)
Risks   :
%s`, a.File, a.Name, a.TargetVersion, strings.Join(risks, "\n")), "\n")
}

func Analyze(file string, m *manifest.Manifest, nsc *manifest.NetworkSecurityConfig) (*Analysis, error) {
	ret := &Analysis{
		File:          file,
		Name:          m.Application.Name,
		TargetVersion: SDKVersionToAndroidMajor(m.UsesSDK.TargetSDKVersion),
		m:             m,
		nsc:           nsc,
	}

	// Android 7+ supports NSC
	// Android 9+ disables cleartext traffic by default

	ret.defaults = AndroidDefaults{
		AllowCleartext: ret.TargetVersion < 9,
		NSCPresence:    ret.TargetVersion >= 7,
	}

	ret.Risks = ret.check()

	return ret, nil
}

func main() {
	flag.Parse()

	for _, file := range flag.Args() {
		m, zip, err := ParseAPK(file)
		if err != nil {
			log.Printf(`cannot parse APK "%s": %v`, file, err)
			continue
		}
		defer zip.Close()

		nsc := (*manifest.NetworkSecurityConfig)(nil)
		if m.Application.NetworkSecurityConfig != "" {
			if zipFile, ok := zip.File[m.Application.NetworkSecurityConfig]; ok {
				if err := zipFile.Open(); err != nil {
					log.Printf(`cannot read nsc of "%s": %v`, file, err)
				} else {
					buffer := new(bytes.Buffer)
					encoder := xml.NewEncoder(buffer)
					currentNSC := manifest.NetworkSecurityConfig{}
					if err := apkparser.ParseXml(zipFile, encoder, nil); err != nil {
						log.Printf(`cannot parse nsc of "%s": %v`, file, err)
					} else if err := xml.Unmarshal(buffer.Bytes(), &currentNSC); err != nil {
						log.Printf(`cannot parse nsc of "%s": %v`, file, err)
					} else {
						nsc = &currentNSC
					}
				}
			} else {
				log.Printf(`cannot find nsc of "%s": %v`, file, err)
			}
		}

		analysis, err := Analyze(file, m, nsc)
		if err != nil {
			log.Printf(`cannot analyze "%s": %v`, file, err)
			continue
		}

		fmt.Println(analysis)
	}
}
