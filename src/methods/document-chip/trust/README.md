# Embedded CSCA trust

`DE_ML_<date>.ml` is the German CSCA master list, published by BSI
(bsi.bund.de, "German Master List"; commercial use permitted provided it is
not used for advertising and does not imply cooperation with BSI). It is a
CMS SignedData; the issuer verifies its signature against the pinned
`csca-germany` fingerprint in `../trust.go` before trusting any certificate
in it. Refresh procedure: docs/document-chip-anchor.md, "Updating the CSCA
trust".
