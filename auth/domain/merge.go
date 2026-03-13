package domain

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// deepMergeMaps merges override into base recursively, returning a new map.
// For nested maps, values are merged recursively.
// For all other types, override replaces base.
func deepMergeMaps(base, override map[string]any) map[string]any {
	result := make(map[string]any, len(base))
	for k, v := range base {
		result[k] = v
	}
	for k, v := range override {
		if baseVal, ok := result[k]; ok {
			baseMap, baseIsMap := baseVal.(map[string]any)
			overMap, overIsMap := v.(map[string]any)
			if baseIsMap && overIsMap {
				result[k] = deepMergeMaps(baseMap, overMap)
				continue
			}
		}
		result[k] = v
	}
	return result
}

// loadTOMLMap reads a TOML file and returns its contents as a raw map.
// Returns nil, nil if the file does not exist.
func loadTOMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// toTOMLMap converts a struct to a TOML map via marshal/unmarshal round-trip.
// Fields tagged with omitempty are excluded when they hold zero values,
// ensuring they don't override higher-priority layers during merge.
func toTOMLMap(v any) (map[string]any, error) {
	data, err := toml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mergeConfigLayers deep-merges multiple TOML maps in order and unmarshals
// the result into dst. Later layers have higher priority.
// Nil layers are skipped.
func mergeConfigLayers(dst any, layers ...map[string]any) error {
	merged := make(map[string]any)
	for _, layer := range layers {
		if layer == nil {
			continue
		}
		merged = deepMergeMaps(merged, layer)
	}
	data, err := toml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	if err := toml.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("unmarshal merged config: %w", err)
	}
	return nil
}
