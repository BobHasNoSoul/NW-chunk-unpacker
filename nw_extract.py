#!/usr/bin/env python3
"""
Neverwinter Online Mod 9 - Chunk + HOG Extractor
================================================
Uses foldercacheClumps.txt as the index for .chunk files.
Uses hoglib binary format spec for .hogg files.

USAGE
-----
  # Extract all chunk files (76k+ files with proper paths):
  python nw_extract.py foldercacheClumps.txt <MasterDisk_folder> [output_dir]

"""

import os, sys, re, zlib, struct

# ──────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────

# From hoglib.h / hoglib.c
HOG_HEADER_FLAG  = 0xDEADF00D
HOG_HEADER_SIZE  = 24   # U32 + U16 + U16 + U32 + U32 + U32 + U32
HOG_FH_SIZE      = 32   # HogFileHeader with alignment padding
HOG_EA_SIZE      = 16   # HogEAHeader
HOGEA_NOT_IN_USE = 1

# From piglib.c no_compress_extensions list
NO_COMPRESS_EXTS = {'.fsb', '.fev', '.bcn', '.hogg', '.hog', '.mset', '.bik'}


# ──────────────────────────────────────────────────────────────────
# HOG EXTRACTOR
# ──────────────────────────────────────────────────────────────────
#
# HOG binary layout:
#   [0]                      HogHeader       (24 bytes)
#   [+op_journal_size]       Op Journal      (zeroed)
#   [+dl_journal_size]       DataList Journal
#   [+file_list_size]        FileList        (array of HogFileHeader, 32 bytes each)
#   [+ea_list_size]          EAList          (array of HogEAHeader,   16 bytes each)
#   [data_section_offset]    File data       (concatenated blobs)
#
# HogHeader (24 bytes LE):
#   U32  hog_header_flag    = 0xDEADF00D
#   U16  version            = 10 or 11
#   U16  op_journal_size
#   U32  file_list_size
#   U32  ea_list_size
#   U32  datalist_fileno    index of internal ?DataList file
#   U32  dl_journal_size
#
# HogFileHeader (32 bytes LE, includes 4-byte alignment pad):
#   U64  offset             byte offset from start of data section
#   U32  size               bytes on disk
#   U32  timestamp
#   U32  checksum           first 32 bits of MD5
#   U32  pad                alignment padding
#   U64  headerdata         union: {pack_size U32, unpacked_size U32}
#
# HogEAHeader (16 bytes LE):
#   U32  name_id            byte offset into DataList string blob
#   U32  header_data_id
#   U32  unpacked_size      decompressed file size
#   U32  flags              bit0 = HOGEA_NOT_IN_USE

def _parse_filelist(data, offset, count):
    entries = []
    for i in range(count):
        p = offset + i * HOG_FH_SIZE
        file_offset, disk_size, timestamp, checksum, pad, headerdata = \
            struct.unpack_from('<QIIIIQ', data, p)
        pack_size    =  headerdata        & 0xFFFFFFFF
        unpacked_hdr = (headerdata >> 32) & 0xFFFFFFFF
        entries.append(dict(offset=file_offset, size=disk_size,
                            timestamp=timestamp, checksum=checksum,
                            pack_size=pack_size, unpacked_hdr=unpacked_hdr))
    return entries


def _parse_ealist(data, offset, count):
    entries = []
    for i in range(count):
        p = offset + i * HOG_EA_SIZE
        name_id, hdr_data_id, unpacked_size, flags = \
            struct.unpack_from('<IIII', data, p)
        entries.append(dict(name_id=name_id, header_data_id=hdr_data_id,
                            unpacked_size=unpacked_size,
                            in_use=not (flags & HOGEA_NOT_IN_USE)))
    return entries


def _parse_datalist(raw):
    """Scan DataList blob for all null-terminated strings, return {offset: name}."""
    names = {}
    pos = 0
    while pos < len(raw):
        end = raw.find(b'\x00', pos)
        if end == -1:
            break
        s = raw[pos:end].decode('utf-8', errors='replace')
        if s:
            names[pos] = s
        pos = end + 1
    return names


def extract_hog(hog_path, output_dir):
    print(f"\nExtracting HOG: {os.path.basename(hog_path)}")
    print(f"  Size: {os.path.getsize(hog_path):,} bytes")

    with open(hog_path, 'rb') as f:
        data = f.read()

    if len(data) < HOG_HEADER_SIZE:
        print("  ERROR: file too small"); return 0

    # Parse HogHeader
    flag, version, op_journal_size, file_list_size, ea_list_size, \
        datalist_fileno, dl_journal_size = \
        struct.unpack_from('<IHHI III', data, 0)

    if flag != HOG_HEADER_FLAG:
        print(f"  ERROR: bad magic 0x{flag:08x} (expected 0x{HOG_HEADER_FLAG:08x})")
        return 0

    num_files = file_list_size // HOG_FH_SIZE
    num_ea    = ea_list_size   // HOG_EA_SIZE
    print(f"  Version: {version}  File slots: {num_files}  EA slots: {num_ea}  DataList idx: {datalist_fileno}")

    filelist_off     = HOG_HEADER_SIZE + op_journal_size + dl_journal_size
    ealist_off       = filelist_off  + file_list_size
    data_section_off = ealist_off   + ea_list_size

    filelist = _parse_filelist(data, filelist_off, num_files)
    ealist   = _parse_ealist(data, ealist_off, num_ea)

    # Load DataList (filenames)
    names = {}
    if datalist_fileno < len(filelist):
        dl = filelist[datalist_fileno]
        dl_abs = data_section_off + dl['offset']
        dl_sz  = dl['size']
        if dl_sz > 0 and dl_abs + dl_sz <= len(data):
            raw_dl = data[dl_abs:dl_abs + dl_sz]
            if raw_dl[:1] in (b'\x78',):
                try: raw_dl = zlib.decompress(raw_dl)
                except: pass
            names = _parse_datalist(raw_dl)
            print(f"  DataList: {len(names)} filename entries")

    os.makedirs(output_dir, exist_ok=True)
    extracted = skipped = errors = 0

    for i in range(num_ea):
        ea = ealist[i]
        if not ea['in_use']:
            skipped += 1
            continue
        if i >= len(filelist):
            skipped += 1
            continue

        fh       = filelist[i]
        filename = names.get(ea['name_id'], f'unknown_{i:04d}.bin')

        # Skip internal files
        if filename.startswith('?'):
            skipped += 1
            continue

        file_abs  = data_section_off + fh['offset']
        disk_size = fh['size']
        unpacked  = ea['unpacked_size']

        if disk_size == 0:
            skipped += 1
            continue
        if file_abs + disk_size > len(data):
            errors += 1
            if errors <= 10:
                print(f"  ERROR {filename}: offset out of range")
            continue

        try:
            raw = data[file_abs:file_abs + disk_size]
            ext = os.path.splitext(filename)[1].lower()
            if unpacked > 0 and unpacked != disk_size and ext not in NO_COMPRESS_EXTS:
                file_data = zlib.decompress(raw)
            else:
                file_data = raw

            out_path = os.path.join(output_dir,
                                    filename.strip('"').replace('/', os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as out:
                out.write(file_data)

            extracted += 1
            if extracted <= 10:
                print(f"  [{i:04d}] {filename}  ({len(file_data):,} bytes)")

        except Exception as e:
            errors += 1
            if errors <= 10:
                print(f"  ERROR [{i}] {filename}: {e}")

    print(f"\n  Done: {extracted} extracted, {skipped} skipped, {errors} errors -> {output_dir}")
    return extracted


# ──────────────────────────────────────────────────────────────────
# CHUNK EXTRACTOR (foldercacheClumps.txt index)
# ──────────────────────────────────────────────────────────────────

def _is_raw(path, size, packed_size):
    if packed_size == 0:            return True
    if packed_size == size:         return True  # stored uncompressed
    ext = os.path.splitext(path)[1].lower()
    return ext in NO_COMPRESS_EXTS


def parse_foldercache_clumps(path):
    print(f"Parsing {os.path.basename(path)} ...")
    with open(path, 'r', errors='replace') as f:
        content = f.read()

    chunk_names = re.findall(r'^Hogorchunkname (.+)$', content, re.MULTILINE)
    chunk_names = [n.strip().strip('"') for n in chunk_names]
    print(f"  {len(chunk_names)} chunk slots, {sum(1 for n in chunk_names if n)} non-empty")

    clumps = []
    for m in re.finditer(r'Clump\n\{(.*?)\}', content, re.DOTALL):
        body = m.group(1)
        c = {'chunkid': 0, 'offset': 0, 'size': 0}
        for field in ['Chunkid', 'Offset', 'Size']:
            fm = re.search(rf'\t{field}\s+(\d+)', body)
            if fm: c[field.lower()] = int(fm.group(1))
        clumps.append(c)
    print(f"  {len(clumps)} clumps")

    files = []
    for block in content.split('\nFiles\n{')[1:]:
        if re.search(r'\tIs_Dir\s+1', block): continue
        path_m   = re.search(r'^\tPath\s+(.+)$',         block, re.MULTILINE)
        pig_m    = re.search(r'^\tPig_Index\s+(-?\d+)',   block, re.MULTILINE)
        offset_m = re.search(r'^\tOffset\s+(\d+)',        block, re.MULTILINE)
        size_m   = re.search(r'\t\tSize\s+(\d+)',         block)
        packed_m = re.search(r'^\tPacked_Size\s+(\d+)',   block, re.MULTILINE)
        if not path_m or not pig_m: continue
        pig = int(pig_m.group(1))
        if pig < 0 or pig >= len(clumps): continue

        fp = path_m.group(1).strip().strip('"')
        parts = fp.replace('\\', '/').split('/')
        fp = '/'.join(p.translate(str.maketrans('<>:"|?*', '_______')) for p in parts)

        files.append(dict(path=fp, pig_index=pig,
                          offset=int(offset_m.group(1)) if offset_m else 0,
                          size=int(size_m.group(1)) if size_m else 0,
                          packed_size=int(packed_m.group(1)) if packed_m else 0))

    print(f"  {len(files)} extractable files")
    return chunk_names, clumps, files


def extract_chunks(foldercache_path, masterdisk_dir, output_dir):
    chunk_names, clumps, files = parse_foldercache_clumps(foldercache_path)

    handles = {}
    missing = set()

    def get_fh(chunkid):
        if chunkid in handles: return handles[chunkid]
        if chunkid in missing: return None
        name = chunk_names[chunkid] if chunkid < len(chunk_names) else ''
        if not name: missing.add(chunkid); return None
        p = os.path.join(masterdisk_dir, name)
        if not os.path.exists(p):
            print(f"  WARNING: missing chunk: {name}")
            missing.add(chunkid); return None
        fh = open(p, 'rb')
        handles[chunkid] = fh
        print(f"  Opened: {name}")
        return fh

    os.makedirs(output_dir, exist_ok=True)
    extracted = skipped = errors = 0

    print(f"\nExtracting {len(files)} files -> {output_dir}")
    for i, entry in enumerate(files):
        if i % 5000 == 0 and i > 0:
            print(f"  {i}/{len(files)} | ok={extracted} skip={skipped} err={errors}")

        clump = clumps[entry['pig_index']]
        fh    = get_fh(clump['chunkid'])
        if fh is None: skipped += 1; continue

        byte_off  = clump['offset'] + entry['offset']
        read_size = entry['packed_size'] if entry['packed_size'] > 0 else entry['size']
        if read_size == 0: skipped += 1; continue

        try:
            fh.seek(byte_off)
            raw = fh.read(read_size)
            file_data = raw if _is_raw(entry['path'], entry['size'], entry['packed_size']) \
                           else zlib.decompress(raw)
            out_path = os.path.join(output_dir, entry['path'].replace('/', os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as out: out.write(file_data)
            extracted += 1
        except Exception as e:
            errors += 1
            if errors <= 20: print(f"  ERROR {entry['path']}: {e}")

    for fh in handles.values(): fh.close()
    print(f"\nFinished: {extracted} extracted, {skipped} skipped, {errors} errors")

    missing_names = sorted(set(chunk_names[c] for c in missing
                               if c < len(chunk_names) and chunk_names[c]))
    if missing_names:
        print("\nMissing chunk files:")
        for n in missing_names: print(f"  {n}")


# ──────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)

    if sys.argv[1] == '--hog':
        if len(sys.argv) < 3:
            print("Usage: nw_extract.py --hog <file.hogg> [output_dir]"); sys.exit(1)
        hog_file   = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 else \
                     os.path.splitext(os.path.basename(hog_file))[0] + '_extracted'
        extract_hog(hog_file, output_dir)
    else:
        if len(sys.argv) < 3:
            print("Usage: nw_extract.py <foldercacheClumps.txt> <MasterDisk_folder> [output_dir]")
            sys.exit(1)
        extract_chunks(sys.argv[1], sys.argv[2],
                       sys.argv[3] if len(sys.argv) > 3 else 'extracted_mod9')
