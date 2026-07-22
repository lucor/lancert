package certstore

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	"lucor.dev/lancert/internal/privateip"
)

const formatVersionFile = ".format-version"

// MigrateLegacy converts every legacy three-file certificate directory into a
// versioned bundle. It is idempotent and never removes the source files.
// Call it once during startup before serving certificates.
func (s *Store) MigrateLegacy() error {
	dirs, err := os.ReadDir(s.baseDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read legacy certificate store: %w", err)
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		parsed, parseErr := parseLegacyDirName(dir.Name())
		if parseErr != nil {
			continue
		}
		bundlePath := filepath.Join(s.baseDir, dir.Name(), bundleFile)
		if _, err := os.Stat(bundlePath); err == nil {
			continue
		}
		bundle, err := s.Load(parsed)
		if err != nil {
			return fmt.Errorf("load legacy bundle %s: %w", dir.Name(), err)
		}
		if bundle == nil {
			continue
		}
		if err := s.SaveBundle(parsed, bundle); err != nil {
			return fmt.Errorf("migrate legacy bundle %s: %w", dir.Name(), err)
		}
		slog.Info("certstore: migrated legacy certificate", "addr", parsed)
	}
	if err := atomicWrite(filepath.Join(s.baseDir, formatVersionFile), []byte("1\n")); err != nil {
		return fmt.Errorf("write certificate store format marker: %w", err)
	}
	return nil
}

func parseLegacyDirName(name string) (netip.Addr, error) {
	// Reuse the same private-IP parser used by Inventory without importing
	// service-level validation rules into the store.
	return privateip.ParseSubdomain(name)
}
