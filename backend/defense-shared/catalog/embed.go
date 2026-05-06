package catalog

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed detectors.seed.yaml
var defaultCatalogYAML []byte

// LoadDefault returns the embedded detector catalog so containers can start
// without depending on sidecar-mounted YAML files.
func LoadDefault() (*Catalog, error) {
	var catalog Catalog
	if err := yaml.Unmarshal(defaultCatalogYAML, &catalog); err != nil {
		return nil, err
	}

	return &catalog, nil
}
