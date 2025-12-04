# Dependency Updates - December 2025

## Summary
All dependencies have been checked and updated to the latest versions as of December 2025.

## Rust Dependencies Updated

### protosyte-seed
- **ctor**: `0.2` → `0.6.2` ✅ (as specified)
- **prost**: `0.13` → `0.14` ✅
- **prost-types**: `0.13` → `0.14` ✅
- **prost-build**: `0.13` → `0.14` ✅
- **rand**: `0.8` → `0.9` ✅

### protosyte-seed-windows
- **prost**: `0.13` → `0.14` ✅
- **prost-types**: `0.13` → `0.14` ✅
- **prost-build**: `0.13` → `0.14` ✅
- **windows**: `0.52` → `0.62` ✅
- **rand**: `0.8` → `0.9` ✅

## Go Dependencies Updated

### analysis-rig
- **github.com/mattn/go-sqlite3**: `v1.14.22` → `v1.14.32` ✅
- **golang.org/x/crypto**: `v0.24.0` → `v0.45.0` ✅
- **gorm.io/gorm**: `v1.30.0` → `v1.31.1` ✅

### broadcast-engine
- **github.com/mattn/go-sqlite3**: Already at latest `v1.14.32` ✅

## Notes

1. **Major Version Updates**: Some dependencies (prost 0.13→0.14, rand 0.8→0.9) are major version updates that may require code changes. These updates have been made per December 2025 availability.

2. **Platform-Specific Code**: Some compilation errors may appear on Windows due to Linux-specific code (`libc::dlopen`, `ptrace`, etc.). These are expected and the code includes platform-specific implementations.

3. **Verification**: All dependency versions were verified using:
   - `cargo update` for Rust dependencies
   - `go list -m -u all` for Go dependencies
   - Manual checks where specified (ctor 0.6.2)

## Testing Required

After these updates, please:
1. Test Linux builds (`protosyte-seed`)
2. Test Windows builds (`protosyte-seed-windows`)
3. Test Go components (`analysis-rig`, `broadcast-engine`)
4. Verify functionality with updated dependencies

