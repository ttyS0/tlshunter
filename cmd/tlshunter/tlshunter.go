package main

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/avast/apkparser"
	"github.com/sigeryang/tlshunter/internal/manifest"
)

func ParseAPK(file string) (*apkparser.ZipReader, *manifest.Manifest, *apkparser.ResourceTable, error) {
	zip, err := apkparser.OpenZip(file)

	if err != nil {
		return nil, nil, nil, fmt.Errorf(`open zip error: %v`, err)
	}

	buf := new(bytes.Buffer)
	encoder := xml.NewEncoder(buf)
	rErr, mErr := apkparser.ParseApkWithZip(zip, encoder)

	if mErr != nil {
		return nil, nil, nil, fmt.Errorf(`parse manifest error: %v`, mErr)
	}

	if rErr != nil {
		return nil, nil, nil, fmt.Errorf(`parse resources error: %v`, rErr)
	}

	m := manifest.Manifest{}
	if err := xml.Unmarshal(buf.Bytes(), &m); err != nil {
		log.Printf(`unmarshal manifest error: %v`, err)
	}

	resourcesFile := zip.File["resources.arsc"]
	if resourcesFile == nil {
		return nil, nil, nil, fmt.Errorf("cannot find resources file")
	}
	if err := resourcesFile.Open(); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open resources.arsc: %v", err)
	}
	defer resourcesFile.Close()

	resources, err := apkparser.ParseResourceTable(resourcesFile)

	if err != nil {
		return nil, nil, nil, fmt.Errorf(`parse resources error: %v`, rErr)
	}

	return zip, &m, resources, nil
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

	zip       *apkparser.ZipReader
	resources *apkparser.ResourceTable
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
	RiskAnchorsOverridePinning
	RiskUnpinned
	RiskPinningExpiration
	RiskProxyAnchors
	RiskMalformedNSC
)

func (t RiskType) Description() string {
	switch t {
	case RiskNSCMissing:
		return "Android network security configuration is missing."
	case RiskCleartext:
		return "Allow cleartext traffic to be transferred."
	case RiskUserAnchors:
		return "Allow users to trust 3rd-party CAs."
	case RiskAnchorsOverridePinning:
		return "Trust anchors override pinned certificates."
	case RiskUnpinned:
		return "Does not pin any certificates."
	case RiskProxyAnchors:
		return "Trust anchors contain proxy tool CA."
	case RiskMalformedNSC:
		return "Domains in NSC contain invalid hostnames."
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
			if baseConfig == nil {
				if defaults.AllowCleartext {
					ret = append(ret, Risk{
						Type:   RiskCleartext,
						Reason: fmt.Sprintf("%s defaults permit cleartext traffic.", section),
					})
				}
			} else {
				if baseConfig.CleartextTrafficPermitted == nil {
					if defaults.AllowCleartext {
						ret = append(ret, Risk{
							Type:   RiskCleartext,
							Reason: fmt.Sprintf("%s defaults permit cleartext traffic.", section),
						})
					}
				} else if *baseConfig.CleartextTrafficPermitted {
					ret = append(ret, Risk{
						Type:   RiskCleartext,
						Reason: fmt.Sprintf("%s permits cleartext traffic.", section),
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
								Type:   RiskAnchorsOverridePinning,
								Reason: fmt.Sprintf("%s override certificate pinning.", section),
							})
						}

						if certs.Src != "system" && certs.Src != "user" {
							res := strings.TrimPrefix(certs.Src, "@")
							resId, err := strconv.ParseInt(res, 16, 32)
							if err != nil {
								continue
							}
							entry, err := a.resources.GetResourceEntry(uint32(resId))
							if err != nil {
								continue
							}
							filename, _ := entry.GetValue().String()
							if err := a.zip.File[filename].Open(); err != nil {
								continue
							}
							ca, err := io.ReadAll(a.zip.File[filename])
							if err != nil {
								continue
							}
							cert, err := x509.ParseCertificate(ca)
							if err != nil {
								continue
							}
							if strings.Contains(strings.ToLower(cert.Subject.String()), "proxy") {
								ret = append(ret, Risk{
									Type:   RiskUserAnchors,
									Reason: fmt.Sprintf(`%s contain proxy tool CA with subject "%s".`, section, cert.Subject.String()),
								})
							}
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
				for _, domain := range domainConfig.Domains {
					if strings.HasPrefix(domain.Data, "http") {
						ret = append(ret, Risk{
							Type:   RiskMalformedNSC,
							Reason: fmt.Sprintf(`%s domains contain malformed hostname "%s".`, section, domain.Data),
						})
					}
				}
				if domainConfig.TrustAnchors != nil {
					for _, certs := range domainConfig.TrustAnchors.Certificates {
						if certs.Src != "system" && certs.Src != "user" {
							res := strings.TrimPrefix(certs.Src, "@")
							resId, err := strconv.ParseInt(res, 16, 32)
							if err != nil {
								continue
							}
							entry, err := a.resources.GetResourceEntry(uint32(resId))
							if err != nil {
								continue
							}
							filename, _ := entry.GetValue().String()
							if err := a.zip.File[filename].Open(); err != nil {
								continue
							}
							ca, err := io.ReadAll(a.zip.File[filename])
							if err != nil {
								continue
							}
							cert, err := x509.ParseCertificate(ca)
							if err != nil {
								continue
							}
							if strings.Contains(strings.ToLower(cert.Subject.String()), "proxy") {
								ret = append(ret, Risk{
									Type:   RiskUserAnchors,
									Reason: fmt.Sprintf(`%s trust anchors contain proxy tool CA with subject "%s".`, section, cert.Subject.String()),
								})
							}
						}
					}
				}
			}

			if !pinned {
				ret = append(ret, Risk{
					Type:   RiskUnpinned,
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
				Reason: fmt.Sprintf("%s permits cleartext traffic.", section),
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

func Analyze(file string, m *manifest.Manifest, nsc *manifest.NetworkSecurityConfig, zip *apkparser.ZipReader, resources *apkparser.ResourceTable) (*Analysis, error) {
	ret := &Analysis{
		File:          file,
		Name:          m.Application.Name,
		TargetVersion: SDKVersionToAndroidMajor(m.UsesSDK.TargetSDKVersion),
		m:             m,
		nsc:           nsc,
		zip:           zip,
		resources:     resources,
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

	riskMap := make(map[RiskType]map[string][]*Analysis)

	for _, file := range flag.Args() {
		zip, m, resources, err := ParseAPK(file)
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

		analysis, err := Analyze(file, m, nsc, zip, resources)
		if err != nil {
			log.Printf(`cannot analyze "%s": %v`, file, err)
			continue
		}

		for _, risk := range analysis.Risks {
			if riskMap[risk.Type] == nil {
				riskMap[risk.Type] = make(map[string][]*Analysis)
			}
			reasonMap := riskMap[risk.Type]
			reasonMap[risk.Reason] = append(reasonMap[risk.Reason], analysis)
		}

		fmt.Println(analysis)
		fmt.Println()
	}

	fmt.Println("Statistics:")
	fmt.Println()
	for riskType, reasonMap := range riskMap {
		total := 0

		for _, apps := range reasonMap {
			total += len(apps)
		}
		fmt.Printf("Risk: %v Count: %d\n", riskType, total)

		for reason, apps := range reasonMap {
			total += len(apps)
			fmt.Printf("    Reason: %s Count: %d\n", reason, len(apps))
			for _, app := range apps {
				fmt.Printf("        File: %s Name: %s\n", app.File, app.Name)
			}
		}
		fmt.Println()
	}
}
