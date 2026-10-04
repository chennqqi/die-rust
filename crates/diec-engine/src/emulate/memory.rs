//! Bounded guest-memory manager for the x86 emulator.
//!
//! Faithful port of upstream `xemumemorymanager.cpp` (pin `655e6da`),
//! restricted to the API surface the static unpackers use: page-granular
//! fixed mappings, zero-filled commit, and little-endian typed accessors.
//! Region flags are stored as metadata exactly like upstream — plain
//! `read`/`write`/`fetch` check COMMIT coverage only, never the flags, so
//! an RWX-vs-RW distinction cannot change observable behavior here.

/// Page granularity used for mapping normalization.
pub const PAGE_SIZE: u64 = 0x1000;
/// Upper bound on a single read/write request (upstream `N_MAX_TOTAL_COMMIT`).
pub const MAX_TOTAL_COMMIT: u64 = 512 * 1024 * 1024;
/// Upper bound on the region table length (upstream `N_MAX_REGIONS`).
pub const MAX_REGIONS: usize = 65536;

/// Access flags recorded per region (metadata only — not enforced).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryFlags {
    /// Region is readable.
    pub read: bool,
    /// Region is writable.
    pub write: bool,
    /// Region holds executable code.
    pub exec: bool,
    /// Region is a guard page.
    pub guard: bool,
}

impl MemoryFlags {
    /// Convenience constructor matching upstream `MEMORY_FLAGS(r,w,x,g)`.
    pub fn new(read: bool, write: bool, exec: bool, guard: bool) -> Self {
        Self {
            read,
            write,
            exec,
            guard,
        }
    }
}

/// One committed, zero-initialized region.
#[derive(Clone)]
pub struct Region {
    /// Start address (page-aligned).
    pub address: u64,
    /// Region length in bytes (page multiple).
    pub size: u64,
    /// Declared access flags.
    pub flags: MemoryFlags,
    /// Region name (diagnostics only).
    pub name: String,
    /// Zero-initialized backing bytes.
    pub data: Vec<u8>,
}

/// Sorted, non-overlapping list of committed regions.
#[derive(Default)]
pub struct MemoryManager {
    regions: Vec<Region>,
    min_address: u64,
    max_address: u64,
    bits: u8,
}

impl MemoryManager {
    /// Create an empty manager in the upstream default state (64-bit
    /// address limits); call [`Self::set_bits`] to switch to 32-bit.
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            min_address: 0x10000,
            max_address: 0x0000_7FFF_FFFF_0000,
            bits: 64,
        }
    }

    /// Switch between 32-bit and 64-bit address limits. Mirrors upstream:
    /// the change is rejected once regions exist and the width differs.
    /// Accepted widths are 32 and 64 only.
    pub fn set_bits(&mut self, bits: u8) {
        if (bits != 32 && bits != 64) || (!self.regions.is_empty() && bits != self.bits) {
            return;
        }
        self.bits = bits;
        self.min_address = 0x10000;
        self.max_address = if bits == 32 {
            0x7FFF_0000
        } else {
            0x0000_7FFF_FFFF_0000
        };
    }

    /// Current address width.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// All regions in address order (for state dumps and diffs).
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// `alignUp` from upstream.
    pub fn align_up(value: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return value;
        }
        value
            .checked_add(alignment - 1)
            .map_or(0, |v| v - (v % alignment))
    }

    /// `alignDown` from upstream.
    pub fn align_down(value: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return value;
        }
        value - (value % alignment)
    }

    /// Page-normalize `[address, address+size)` into `[start, end)`.
    /// Fails on zero size, address overflow, empty result, or an end past
    /// the address-width limit — the upstream `_normalizePageRange` rules.
    fn normalize_page_range(&self, address: u64, size: u64) -> Option<(u64, u64)> {
        if size == 0 || address.checked_add(size).is_none() {
            return None;
        }
        let start = Self::align_down(address, PAGE_SIZE);
        let end = Self::align_up(address + size, PAGE_SIZE);
        if end == 0 || end <= start || end > self.max_address {
            return None;
        }
        Some((start, end))
    }

    /// Map a fixed, zero-filled committed region at a page-normalized
    /// address; fails on overlap with any existing region.
    pub fn map_fixed(&mut self, address: u64, size: u64, flags: MemoryFlags, name: &str) -> bool {
        if self.regions.len() >= MAX_REGIONS {
            return false;
        }
        let Some((start, end)) = self.normalize_page_range(address, size) else {
            return false;
        };
        for region in &self.regions {
            let region_end = region.address.saturating_add(region.size);
            if start < region_end && region.address < end {
                return false;
            }
        }
        let Ok(size) = usize::try_from(end - start) else {
            return false;
        };
        let index = self
            .regions
            .iter()
            .position(|r| r.address > start)
            .unwrap_or(self.regions.len());
        self.regions.insert(
            index,
            Region {
                address: start,
                size: end - start,
                flags,
                name: name.to_string(),
                data: vec![0u8; size],
            },
        );
        true
    }

    /// Index of the region containing `address`, if any.
    fn find_containing(&self, address: u64) -> Option<usize> {
        self.regions
            .iter()
            .position(|r| address >= r.address && address - r.address < r.size)
    }

    /// Whether `[address, address+size)` is fully covered by committed
    /// regions (upstream `isCommitted`; no flag check).
    pub fn is_committed(&self, address: u64, size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        let mut cursor = address;
        while cursor < end {
            let Some(index) = self.find_containing(cursor) else {
                return false;
            };
            let region = &self.regions[index];
            cursor = region.address.saturating_add(region.size);
        }
        true
    }

    /// Read `buffer.len()` bytes; fails unless the whole range is
    /// committed (upstream `read`).
    pub fn read_into(&self, address: u64, buffer: &mut [u8]) -> bool {
        if buffer.is_empty() {
            return true;
        }
        let size = buffer.len() as u64;
        if size > MAX_TOTAL_COMMIT
            || address.checked_add(size).is_none()
            || !self.is_committed(address, size)
        {
            return false;
        }
        let mut done = 0u64;
        while done < size {
            let current = address + done;
            let Some(index) = self.find_containing(current) else {
                return false;
            };
            let region = &self.regions[index];
            let offset = (current - region.address) as usize;
            let chunk = ((region.size - (current - region.address)) as usize)
                .min(buffer.len() - done as usize);
            buffer[done as usize..done as usize + chunk]
                .copy_from_slice(&region.data[offset..offset + chunk]);
            done += chunk as u64;
        }
        true
    }

    /// Read `size` bytes into a new vector (upstream `read` -> QByteArray).
    /// Fails on uncommitted ranges or `size` over the commit bound.
    pub fn read(&self, address: u64, size: u64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(size).ok()?];
        self.read_into(address, &mut buf).then_some(buf)
    }

    /// Write `data`; fails unless the whole range is committed
    /// (upstream `write`).
    pub fn write(&mut self, address: u64, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let size = data.len() as u64;
        if size > MAX_TOTAL_COMMIT
            || address.checked_add(size).is_none()
            || !self.is_committed(address, size)
        {
            return false;
        }
        let mut done = 0u64;
        while done < size {
            let current = address + done;
            let Some(index) = self.find_containing(current) else {
                return false;
            };
            let region = &mut self.regions[index];
            let offset = (current - region.address) as usize;
            let chunk = ((region.size - (current - region.address)) as usize)
                .min(data.len() - done as usize);
            region.data[offset..offset + chunk]
                .copy_from_slice(&data[done as usize..done as usize + chunk]);
            done += chunk as u64;
        }
        true
    }

    /// Little-endian byte read; `None` on uncommitted access.
    pub fn read_u8(&self, address: u64) -> Option<u8> {
        let mut b = [0u8; 1];
        self.read_into(address, &mut b).then_some(b[0])
    }

    /// Little-endian word read; `None` on uncommitted access.
    pub fn read_u16(&self, address: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        self.read_into(address, &mut b)
            .then_some(u16::from_le_bytes(b))
    }

    /// Little-endian dword read; `None` on uncommitted access.
    pub fn read_u32(&self, address: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read_into(address, &mut b)
            .then_some(u32::from_le_bytes(b))
    }

    /// Little-endian qword read; `None` on uncommitted access.
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.read_into(address, &mut b)
            .then_some(u64::from_le_bytes(b))
    }

    /// Little-endian byte write; `false` on uncommitted access.
    pub fn write_u8(&mut self, address: u64, value: u8) -> bool {
        self.write(address, &[value])
    }

    /// Little-endian word write; `false` on uncommitted access.
    pub fn write_u16(&mut self, address: u64, value: u16) -> bool {
        self.write(address, &value.to_le_bytes())
    }

    /// Little-endian dword write; `false` on uncommitted access.
    pub fn write_u32(&mut self, address: u64, value: u32) -> bool {
        self.write(address, &value.to_le_bytes())
    }

    /// Little-endian qword write; `false` on uncommitted access.
    pub fn write_u64(&mut self, address: u64, value: u64) -> bool {
        self.write(address, &value.to_le_bytes())
    }

    /// Instruction fetch; identical to [`Self::read_u8`] in this port
    /// (upstream `fetchByte` additionally fires an invalid-access
    /// callback that the unpacker paths never install).
    pub fn fetch_u8(&self, address: u64) -> Option<u8> {
        self.read_u8(address)
    }

    /// Instruction fetch (word); see [`Self::fetch_u8`].
    pub fn fetch_u16(&self, address: u64) -> Option<u16> {
        self.read_u16(address)
    }

    /// Instruction fetch (dword); see [`Self::fetch_u8`].
    pub fn fetch_u32(&self, address: u64) -> Option<u32> {
        self.read_u32(address)
    }

    /// Instruction fetch (qword); see [`Self::fetch_u8`].
    pub fn fetch_u64(&self, address: u64) -> Option<u64> {
        self.read_u64(address)
    }

    /// Lowest address usable by mappings (upstream `m_nMinAddress`).
    pub fn min_address(&self) -> u64 {
        self.min_address
    }
}
