package documentchip

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/sagearbor/personhood/src/methods/document-chip/icao"
)

// The CSCA trust that ships with the issuer: the German master list, which
// BSI publishes free of charge (signed CMS, ~600 CSCA and link certificates
// from ~120 states, including the US and India), re-published by BSI
// roughly monthly. See docs/document-chip-anchor.md, "Updating the CSCA
// trust", for how to refresh it and how to add the ICAO PKD master list or
// another state's list.
//
//go:embed trust/*.ml
var embeddedTrust embed.FS

// GermanCSCASHA256 pins the BSI csca-germany certificate (self-signed,
// "Certificate 10/24") that issues the German master list signer. BSI
// publishes this fingerprint on its CSCA page (bsi.bund.de, "The German
// Country Signing Certificate Authority"); it was checked against that page
// on 2026-11-04. When BSI rolls csca-germany over, add the new fingerprint
// here (keep the old one until the old list is gone).
var GermanCSCASHA256 = []string{
	"2084aed7a991b3158e63ad750d3dc38bc6c9dcf5958f28d1162f49884e91ada8",
}

// DefaultTrust loads the embedded master list(s), newest last, verifying
// each against the pinned anchors.
func DefaultTrust() (*icao.TrustStore, []icao.MasterListInfo, error) {
	names, err := fs.Glob(embeddedTrust, "trust/*.ml")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(names)
	ts := icao.NewTrustStore()
	var infos []icao.MasterListInfo
	for _, n := range names {
		der, err := embeddedTrust.ReadFile(n)
		if err != nil {
			return nil, nil, err
		}
		info, err := ts.AddMasterList(der, GermanCSCASHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("document-chip: %s: %w", n, err)
		}
		infos = append(infos, info)
	}
	if ts.Len() == 0 {
		return nil, nil, fmt.Errorf("document-chip: no embedded master list")
	}
	return ts, infos, nil
}
