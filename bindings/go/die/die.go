// Package die provides Go bindings for the die-rust C ABI.
//
// This package wraps the opaque handle API defined in include/die.h.
// It exposes a Database, Scanner, and one-shot Scan functions with
// automatic resource cleanup via runtime finalizers and explicit Close.
//
// Usage:
//
//	db, err := die.NewDatabase("../../upstream/Detect-It-Easy/db")
//	if err != nil { panic(err) }
//	defer db.Close()
//
//	result, err := die.ScanBytes(db, sevenZipHeader)
//	if err != nil { panic(err) }
//	defer result.Close()
//
//	fmt.Println(result.JSON())
package die

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include

#include <stdlib.h>
#include <stdint.h>
#include "die.h"

// Helper: call scan_bytes and return the result handle directly.
// cgo cannot easily pass ** pointers, so we use these wrappers.
static die_v1_result* cgo_scan_bytes(
    die_v1_database *db,
    const uint8_t *data, uint64_t length,
    uint32_t flags,
    die_v1_error **out_error)
{
    die_v1_result *result = NULL;
    die_v1_scan_options opts;
    die_v1_scan_options_init(&opts, sizeof(opts));
    opts.flags = flags;
    uint32_t status = die_v1_scan_bytes(db, data, length, &opts, NULL, &result, out_error);
    if (status != DIE_STATUS_OK) {
        if (result) die_v1_result_free(&result);
        return NULL;
    }
    return result;
}

static die_v1_result* cgo_scan_path(
    die_v1_database *db,
    const char *path, uint64_t length,
    uint32_t flags,
    die_v1_error **out_error)
{
    die_v1_result *result = NULL;
    die_v1_scan_options opts;
    die_v1_scan_options_init(&opts, sizeof(opts));
    opts.flags = flags;
    uint32_t status = die_v1_scan_path_utf8(db, (const uint8_t*)path, length, &opts, NULL, &result, out_error);
    if (status != DIE_STATUS_OK) {
        if (result) die_v1_result_free(&result);
        return NULL;
    }
    return result;
}

static die_v1_database* cgo_build_database(
    const char *path, uint64_t length,
    die_v1_error **out_error)
{
    die_v1_database_builder *builder = NULL;
    uint32_t status = die_v1_database_builder_new(&builder, out_error);
    if (status != DIE_STATUS_OK) return NULL;

    status = die_v1_database_builder_add_path_utf8(builder, 0,
        (const uint8_t*)path, length, 0, out_error);
    if (status != DIE_STATUS_OK) {
        die_v1_database_builder_free(&builder);
        return NULL;
    }

    die_v1_database *db = NULL;
    status = die_v1_database_builder_build(builder, &db, out_error);
    die_v1_database_builder_free(&builder);
    if (status != DIE_STATUS_OK) return NULL;
    return db;
}

static const uint8_t* cgo_result_json(die_v1_result *r, uint64_t *len) {
    const uint8_t *data = NULL;
    *len = 0;
    die_v1_result_json(r, &data, len);
    return data;
}

static const uint8_t* cgo_result_path(die_v1_result *r, uint64_t *len) {
    const uint8_t *data = NULL;
    *len = 0;
    die_v1_result_path_utf8(r, &data, len);
    return data;
}

static uint64_t cgo_result_count(die_v1_result *r) {
    uint64_t count = 0;
    die_v1_result_detection_count(r, &count);
    return count;
}

static const uint8_t* cgo_error_message(die_v1_error *e, uint64_t *len) {
    const uint8_t *data = NULL;
    *len = 0;
    die_v1_error_message(e, &data, len);
    return data;
}

static uint32_t cgo_error_status(die_v1_error *e) {
    uint32_t status = 0;
    die_v1_error_status(e, &status);
    return status;
}

// Helper: call scanner_scan_bytes (reusable scanner API).
// This reuses the scanner's internal runtime across multiple scans,
// avoiding the per-scan runtime construction cost of the one-shot API.
static die_v1_result* cgo_scanner_scan_bytes(
    die_v1_scanner *scanner,
    const uint8_t *data, uint64_t length,
    uint32_t flags,
    die_v1_error **out_error)
{
    die_v1_result *result = NULL;
    die_v1_scan_options opts;
    die_v1_scan_options_init(&opts, sizeof(opts));
    opts.flags = flags;
    uint32_t status = die_v1_scanner_scan_bytes(scanner, data, length, &opts, NULL, &result, out_error);
    if (status != DIE_STATUS_OK) {
        if (result) die_v1_result_free(&result);
        return NULL;
    }
    return result;
}

// Helper: call scanner_scan_path_utf8 (reusable scanner API).
static die_v1_result* cgo_scanner_scan_path(
    die_v1_scanner *scanner,
    const char *path, uint64_t length,
    uint32_t flags,
    die_v1_error **out_error)
{
    die_v1_result *result = NULL;
    die_v1_scan_options opts;
    die_v1_scan_options_init(&opts, sizeof(opts));
    opts.flags = flags;
    uint32_t status = die_v1_scanner_scan_path_utf8(scanner, (const uint8_t*)path, length, &opts, NULL, &result, out_error);
    if (status != DIE_STATUS_OK) {
        if (result) die_v1_result_free(&result);
        return NULL;
    }
    return result;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Status codes matching die.h.
const (
	StatusOK               = 0
	StatusInvalidArgument  = 1
	StatusAbiMismatch      = 2
	StatusInvalidUTF8      = 3
	StatusIO               = 4
	StatusDatabase         = 5
	StatusUnsupported      = 6
	StatusLimitExceeded    = 7
	StatusCancelled        = 8
	StatusTimeout          = 9
	StatusScript           = 10
	StatusWrongThread      = 11
	StatusBusy             = 12
	StatusPanic            = 13
	StatusInternal         = 14
	StatusAllocationFailed = 15
)

// Scan flag bits.
const (
	FlagDeep        = 0x01
	FlagHeuristic   = 0x02
	FlagAllTypes    = 0x04
	FlagAggressive  = 0x08
	FlagHideUnknown = 0x10
	FlagVerbose     = 0x20
)

// Database holds a loaded rule database.
type Database struct {
	handle *C.die_v1_database
}

// Result holds a scan result.
type Result struct {
	handle *C.die_v1_result
}

// Scanner is a reusable scanner.
type Scanner struct {
	handle *C.die_v1_scanner
}

// NewDatabase builds a database from the given directory path.
func NewDatabase(path string) (*Database, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var err *C.die_v1_error
	db := C.cgo_build_database(cPath, C.uint64_t(len(path)), &err)
	if db == nil {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Database{handle: db}, nil
}

// Close releases the database.
func (db *Database) Close() {
	if db.handle != nil {
		C.die_v1_database_free(&db.handle)
		db.handle = nil
	}
}

// NewScanner creates a reusable scanner from the database.
func (db *Database) NewScanner() (*Scanner, error) {
	var err *C.die_v1_error
	var scanner *C.die_v1_scanner
	status := C.die_v1_scanner_new(db.handle, &scanner, &err)
	if uint32(status) != StatusOK {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Scanner{handle: scanner}, nil
}

// Close releases the scanner.
func (s *Scanner) Close() {
	if s.handle != nil {
		C.die_v1_scanner_free(&s.handle)
		s.handle = nil
	}
}

// ScanBytes scans a byte buffer with the reusable scanner.
//
// This uses the reusable scanner API (die_v1_scanner_scan_bytes) which
// reuses the internal JavaScript runtime across scans, avoiding the
// per-scan runtime construction cost of the one-shot ScanBytes function.
func (s *Scanner) ScanBytes(data []byte, flags uint32) (*Result, error) {
	var err *C.die_v1_error
	var ptr *C.uint8_t
	var length C.uint64_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
		length = C.uint64_t(len(data))
	}
	r := C.cgo_scanner_scan_bytes(s.handle, ptr, length, C.uint32_t(flags), &err)
	if r == nil {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Result{handle: r}, nil
}

// ScanPath scans a file path with the reusable scanner.
//
// This uses the reusable scanner API (die_v1_scanner_scan_path_utf8)
// which reuses the internal JavaScript runtime across scans.
func (s *Scanner) ScanPath(path string, flags uint32) (*Result, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var err *C.die_v1_error
	r := C.cgo_scanner_scan_path(s.handle, cPath, C.uint64_t(len(path)), C.uint32_t(flags), &err)
	if r == nil {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Result{handle: r}, nil
}

// ScanBytes performs a one-shot scan of a byte buffer.
func ScanBytes(db *Database, data []byte, flags uint32) (*Result, error) {
	var err *C.die_v1_error
	var ptr *C.uint8_t
	var length C.uint64_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
		length = C.uint64_t(len(data))
	}
	r := C.cgo_scan_bytes(db.handle, ptr, length, C.uint32_t(flags), &err)
	if r == nil {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Result{handle: r}, nil
}

// ScanPath performs a one-shot scan of a file path.
func ScanPath(db *Database, path string, flags uint32) (*Result, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var err *C.die_v1_error
	r := C.cgo_scan_path(db.handle, cPath, C.uint64_t(len(path)), C.uint32_t(flags), &err)
	if r == nil {
		return nil, makeGoError(err)
	}
	C.die_v1_error_free(&err)
	return &Result{handle: r}, nil
}

// Close releases the result.
func (r *Result) Close() {
	if r.handle != nil {
		C.die_v1_result_free(&r.handle)
		r.handle = nil
	}
}

// JSON returns the canonical JSON representation of the scan result.
func (r *Result) JSON() string {
	var length C.uint64_t
	data := C.cgo_result_json(r.handle, &length)
	if data == nil || length == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(length))
}

// Path returns the scanned file path.
func (r *Result) Path() string {
	var length C.uint64_t
	data := C.cgo_result_path(r.handle, &length)
	if data == nil || length == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(length))
}

// DetectionCount returns the number of detections.
func (r *Result) DetectionCount() uint64 {
	return uint64(C.cgo_result_count(r.handle))
}

// makeGoError converts a C error handle to a Go error.
func makeGoError(err *C.die_v1_error) error {
	if err == nil {
		return errors.New("unknown error")
	}
	defer C.die_v1_error_free(&err)
	status := uint32(C.cgo_error_status(err))
	var length C.uint64_t
	data := C.cgo_error_message(err, &length)
	msg := "unknown"
	if data != nil && length > 0 {
		msg = C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(length))
	}
	return fmt.Errorf("die status %d: %s", status, msg)
}

// AbiVersion returns the library ABI version.
func AbiVersion() uint32 {
	return uint32(C.die_abi_version())
}

// AbiCompatible checks if the library is compatible with the requested version.
func AbiCompatible(requested uint32) bool {
	return C.die_abi_is_compatible(C.uint32_t(requested)) != 0
}
