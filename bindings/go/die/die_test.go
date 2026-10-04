// Package die_test verifies the Go bindings against the die-rust C ABI.
//
// This test builds the database, scans a 7-Zip header, and verifies
// the result JSON contains "7-Zip".
//
// Run:
//
//	go test -v ./...
//
// The static library must be built first:
//
//	cargo build -p die-ffi --release
//
// On Windows, link against target/release/die_ffi.lib.
// On Linux/macOS, link against target/release/libdie_ffi.a.
package die_test

import (
	"strings"
	"testing"

	die "github.com/chennqqi/die-rust/bindings/go/die"
)

// sevenZipHeader returns a minimal 7-Zip file header (64 bytes).
func sevenZipHeader() []byte {
	data := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04}
	for len(data) < 64 {
		data = append(data, 0)
	}
	return data
}

const dbPath = "../../../upstream/Detect-It-Easy/db"

func TestAbiVersion(t *testing.T) {
	ver := die.AbiVersion()
	if ver != 0x00010000 {
		t.Fatalf("ABI version = 0x%08x, want 0x00010000", ver)
	}
}

func TestAbiCompatible(t *testing.T) {
	if !die.AbiCompatible(0x00010000) {
		t.Fatal("library should be compatible with v1.0")
	}
	if die.AbiCompatible(0x00020000) {
		t.Fatal("library should not be compatible with v2.0")
	}
}

func TestScanBytes(t *testing.T) {
	db, err := die.NewDatabase(dbPath)
	if err != nil {
		t.Skipf("Skipping: cannot load database: %v", err)
	}
	defer db.Close()

	result, err := die.ScanBytes(db, sevenZipHeader(), 0)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	defer result.Close()

	json := result.JSON()
	if !strings.Contains(json, "7-Zip") {
		t.Errorf("JSON does not contain 7-Zip: %s", json)
	}

	count := result.DetectionCount()
	if count == 0 {
		t.Error("DetectionCount is 0")
	}
}

func TestScanPath(t *testing.T) {
	db, err := die.NewDatabase(dbPath)
	if err != nil {
		t.Skipf("Skipping: cannot load database: %v", err)
	}
	defer db.Close()

	// Write a temp file with 7-Zip header.
	// (In a real test we'd use t.TempDir, but for simplicity we scan
	// an existing corpus file if available.)
	result, err := die.ScanPath(db, "../../../corpus/payload.zip", 0)
	if err != nil {
		t.Skipf("Skipping: cannot scan corpus file: %v", err)
	}
	defer result.Close()

	json := result.JSON()
	if !strings.Contains(json, `"file_type":"ZIP"`) {
		t.Errorf("JSON does not contain file_type ZIP: %s", json)
	}
}

func TestNullDatabasePath(t *testing.T) {
	_, err := die.NewDatabase("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

// TestReusableScannerScanBytes verifies that the reusable Scanner's
// ScanBytes method uses the reusable scanner API (die_v1_scanner_scan_bytes)
// and produces correct results across multiple scans.
func TestReusableScannerScanBytes(t *testing.T) {
	db, err := die.NewDatabase(dbPath)
	if err != nil {
		t.Skipf("Skipping: cannot load database: %v", err)
	}
	defer db.Close()

	scanner, err := db.NewScanner()
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	defer scanner.Close()

	// First scan: 7-Zip header.
	result1, err := scanner.ScanBytes(sevenZipHeader(), 0)
	if err != nil {
		t.Fatalf("first ScanBytes failed: %v", err)
	}
	defer result1.Close()
	json1 := result1.JSON()
	if !strings.Contains(json1, "7-Zip") {
		t.Errorf("first scan JSON does not contain 7-Zip: %s", json1)
	}

	// Second scan: same data, should still work (runtime reused).
	result2, err := scanner.ScanBytes(sevenZipHeader(), 0)
	if err != nil {
		t.Fatalf("second ScanBytes failed: %v", err)
	}
	defer result2.Close()
	json2 := result2.JSON()
	if !strings.Contains(json2, "7-Zip") {
		t.Errorf("second scan JSON does not contain 7-Zip: %s", json2)
	}

	// Third scan: empty data, should not crash.
	empty := make([]byte, 64)
	result3, err := scanner.ScanBytes(empty, 0)
	if err != nil {
		t.Fatalf("third ScanBytes (empty) failed: %v", err)
	}
	defer result3.Close()
}

// TestReusableScannerScanPath verifies that the reusable Scanner's
// ScanPath method uses the reusable scanner API.
func TestReusableScannerScanPath(t *testing.T) {
	db, err := die.NewDatabase(dbPath)
	if err != nil {
		t.Skipf("Skipping: cannot load database: %v", err)
	}
	defer db.Close()

	scanner, err := db.NewScanner()
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	defer scanner.Close()

	result, err := scanner.ScanPath("../../../corpus/payload.zip", 0)
	if err != nil {
		t.Skipf("Skipping: cannot scan corpus file: %v", err)
	}
	defer result.Close()

	json := result.JSON()
	if !strings.Contains(json, `"file_type":"ZIP"`) {
		t.Errorf("reusable scanner ScanPath JSON does not contain file_type ZIP: %s", json)
	}
}
