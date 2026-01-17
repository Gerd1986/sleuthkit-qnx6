/*
 * The Sleuth Kit
 * QNX6 file system support (read-only)
 *
 * Autopsy-ready behaviors:
 *  - qnx6fs_open initializes TSK_FS_INFO correctly and returns &qfs->fs_info
 *  - dir_open_meta does not double-free TSK_FS_NAME (dir owns entries)
 *  - file_add_meta fills TSK_FS_META fields (type, times, uid/gid, size)
 *  - load_attrs builds a DEFAULT non-resident runlist for content reads
 *  - inode_walk iterates inodes and calls the callback
 *
 * This file assumes little-endian on-disk structures.
 */

#include "tsk_fs_i.h"
#include "qnx6fs.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef _MSC_VER
#include <malloc.h>
#endif

/* MSVC/Windows: ensure these exist */
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

#pragma pack(push, 1)

typedef struct {
    uint8_t magic[4];
    uint32_t offset_qnx6fs;
    uint32_t sblk0;
    uint32_t sblk1;
} QNX6_BOOT;

typedef struct {
    uint64_t size;
    uint32_t ptr[16];
    uint8_t level;
    uint8_t mode;
    uint8_t spare[6];
} QNX6_ROOTNODE;

typedef struct {
    uint8_t magic[4];
    uint32_t crc;
    uint64_t serial;
    uint32_t ctime;
    uint32_t atime;
    uint32_t flag;
    uint16_t version1;
    uint16_t version2;
    uint8_t volumeid[16];
    uint32_t blocksize;
    uint32_t num_inodes;
    uint32_t free_inodes;
    uint32_t num_blocks;
    uint32_t free_blocks;
    uint32_t allocgroup;
    QNX6_ROOTNODE inodes;
    QNX6_ROOTNODE bitmap;
    QNX6_ROOTNODE longfile;
    QNX6_ROOTNODE iclaim;
    QNX6_ROOTNODE iextra;
    uint32_t migrate_blocks;
    uint32_t scrub_block;
    uint8_t spare[32];
} QNX6_SUPER;

typedef struct {
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t ftime;
    uint32_t mtime;
    uint32_t atime;
    uint32_t ctime;
    uint16_t mode;
    uint16_t ext_mode;
    uint32_t ptr[16];
    uint8_t level;
    uint8_t status;
    uint8_t unknown[2];
    uint32_t zeros[6];
} QNX6_INODE;

typedef struct {
    uint32_t inum;
    uint8_t length;
    uint8_t payload[27];
} QNX6_DIRENT;

#pragma pack(pop)

typedef struct {
    TSK_FS_INFO fs_info;
    uint64_t data_start;
    QNX6_SUPER sb;
    QNX6_ROOTNODE rn_inodes;
    QNX6_ROOTNODE rn_longfile;
    QNX6_ROOTNODE rn_bitmap;
} QNX6FS_INFO;

#define QNX6_UNUSED_PTR 0xFFFFFFFFu

/* ---------------- low-level helpers ---------------- */

static TSK_FS_META_TYPE_ENUM
qnx6_mode_to_meta_type(uint16_t mode)
{
    switch (mode & S_IFMT) {
    case S_IFREG: return TSK_FS_META_TYPE_REG;
    case S_IFDIR: return TSK_FS_META_TYPE_DIR;
    case S_IFLNK: return TSK_FS_META_TYPE_LNK;
    case S_IFCHR: return TSK_FS_META_TYPE_CHR;
    case S_IFBLK: return TSK_FS_META_TYPE_BLK;
    case S_IFIFO: return TSK_FS_META_TYPE_FIFO;
#ifdef S_IFSOCK
    case S_IFSOCK: return TSK_FS_META_TYPE_SOCK;
#endif
    default: return TSK_FS_META_TYPE_UNDEF;
    }
}


static int qnx6_read_img(TSK_IMG_INFO *img, TSK_OFF_T off, void *buf, size_t len) {
    ssize_t r = tsk_img_read(img, off, (char*)buf, len);
    return (r != (ssize_t)len);
}

static uint32_t qnx6_crc32_noreflect(const uint8_t *buf, size_t len) {
    uint32_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= ((uint32_t)buf[i] << 24);
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80000000u) crc = (crc << 1) ^ 0x04C11DB7u;
            else crc <<= 1;
        }
    }
    return crc;
}

static int qnx6_check_superblock_512(const uint8_t raw[512], uint64_t *serial_out) {
    uint32_t stored_crc = tsk_getu32(TSK_LIT_ENDIAN, &raw[4]);
    uint32_t calc_crc = qnx6_crc32_noreflect(&raw[8], 512 - 8);
    uint64_t serial = tsk_getu64(TSK_LIT_ENDIAN, &raw[8]);
    if (serial_out) *serial_out = serial;
    return stored_crc == calc_crc;
}

static uint64_t qnx6_data_start(uint32_t bs) {
    if (bs <= 0x1000) return 0x3000;
    if (bs >= 0x3000) return (uint64_t)bs;         /* 0x3000 + (bs-0x3000) */
    return (uint64_t)(0x6000 - bs);                /* 0x3000 + (0x3000-bs) */
}

static int qnx6_read_block(QNX6FS_INFO *qfs, uint32_t blk, uint8_t *out) {
    TSK_OFF_T off = qfs->fs_info.offset + (TSK_OFF_T)qfs->data_start + (TSK_OFF_T)blk * (TSK_OFF_T)qfs->fs_info.block_size;
    return qnx6_read_img(qfs->fs_info.img_info, off, out, qfs->fs_info.block_size);
}

static uint64_t qnx6_bytes_in_unit(uint32_t bs, uint8_t inode_level, uint8_t level) {
    uint64_t mul = 1;
    uint32_t fanout = bs / 4;
    for (int i = 0; i < (int)(inode_level - level); i++) mul *= fanout;
    return (uint64_t)bs * mul;
}

static uint32_t qnx6_ptr_at_offset(QNX6FS_INFO *qfs, const uint32_t ptr0[16], uint8_t inode_level, uint64_t off_bytes) {
    uint32_t bs = (uint32_t)qfs->fs_info.block_size;

    uint64_t unit0 = qnx6_bytes_in_unit(bs, inode_level, 0);
    uint32_t idx = (uint32_t)(off_bytes / unit0);
    if (idx >= 16) return QNX6_UNUSED_PTR;

    uint32_t ptr = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ptr0[idx]);
    if (ptr == QNX6_UNUSED_PTR) return QNX6_UNUSED_PTR;

    if (inode_level == 0) return ptr;

    uint8_t *tmp = (uint8_t*)tsk_malloc(bs);
    if (!tmp) return QNX6_UNUSED_PTR;

    for (uint8_t lvl = 0; lvl < inode_level; lvl++) {
        uint64_t cur_unit = qnx6_bytes_in_unit(bs, inode_level, lvl);
        uint64_t next_unit = qnx6_bytes_in_unit(bs, inode_level, (uint8_t)(lvl + 1));
        uint64_t rem = off_bytes % cur_unit;
        uint32_t idx2 = (uint32_t)(rem / next_unit);

        if (qnx6_read_block(qfs, ptr, tmp)) { free(tmp); return QNX6_UNUSED_PTR; }
        uint32_t *arr = (uint32_t*)tmp;
        ptr = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&arr[idx2]);
        if (ptr == QNX6_UNUSED_PTR) { free(tmp); return QNX6_UNUSED_PTR; }

        off_bytes = rem;
    }

    free(tmp);
    return ptr;
}

static uint8_t *qnx6_read_file_bytes(QNX6FS_INFO *qfs, const uint32_t ptr0[16], uint8_t level,
    uint64_t fsize, uint64_t offset, uint32_t size, uint32_t *out_len)
{
    uint32_t bs = (uint32_t)qfs->fs_info.block_size;
    if (offset >= fsize) { *out_len = 0; return NULL; }

    uint64_t max = fsize - offset;
    if ((uint64_t)size > max) size = (uint32_t)max;

    uint8_t *buf = (uint8_t*)tsk_malloc(size);
    if (!buf) return NULL;

    uint8_t *blkbuf = (uint8_t*)tsk_malloc(bs);
    if (!blkbuf) { free(buf); return NULL; }

    uint64_t cur = offset;
    uint32_t written = 0;
    while (written < size) {
        uint64_t blk_off = (cur / bs) * bs;
        uint32_t ptr = qnx6_ptr_at_offset(qfs, ptr0, level, blk_off);

        if (ptr == QNX6_UNUSED_PTR) {
            memset(blkbuf, 0, bs);
        } else {
            if (qnx6_read_block(qfs, ptr, blkbuf)) { free(blkbuf); free(buf); return NULL; }
        }

        uint32_t in_blk = (uint32_t)(cur % bs);
        uint32_t take = bs - in_blk;
        if (take > (size - written)) take = size - written;
        memcpy(buf + written, blkbuf + in_blk, take);
        written += take;
        cur += take;
    }

    free(blkbuf);
    *out_len = written;
    return buf;
}

static int qnx6_read_inode(QNX6FS_INFO *qfs, TSK_INUM_T inum, QNX6_INODE *out) {
    if (inum < 1 || inum > qfs->fs_info.inum_count) return 1;
    /* inode size is 128 bytes in our parser */
    uint64_t off = (uint64_t)(inum - 1) * 128u;
    uint32_t got = 0;
    uint8_t *raw = qnx6_read_file_bytes(qfs, qfs->rn_inodes.ptr, qfs->rn_inodes.level, qfs->rn_inodes.size,
        off, 128u, &got);
    if (!raw || got != 128u) { if (raw) free(raw); return 1; }
    memcpy(out, raw, sizeof(QNX6_INODE));
    free(raw);
    return 0;
}

static char *qnx6_get_longname(QNX6FS_INFO *qfs, uint32_t index, uint16_t *out_len) {
    uint32_t bs = (uint32_t)qfs->fs_info.block_size;
    uint32_t got = 0;
    uint8_t *blk = qnx6_read_file_bytes(qfs, qfs->rn_longfile.ptr, qfs->rn_longfile.level, qfs->rn_longfile.size,
        (uint64_t)index * bs, bs, &got);
    if (!blk || got < 2) { if (blk) free(blk); return NULL; }

    uint16_t nlen = tsk_getu16(TSK_LIT_ENDIAN, blk);
    if (nlen > bs - 2) nlen = (uint16_t)(bs - 2);

    char *name = (char*)tsk_malloc((size_t)nlen + 1);
    if (!name) { free(blk); return NULL; }

    memcpy(name, blk + 2, nlen);
    name[nlen] = '\0';

    free(blk);
    if (out_len) *out_len = nlen;
    return name;
}

/* ---------------- TSK callbacks ---------------- */

static uint8_t qnx6fs_load_attrs(TSK_FS_FILE *fs_file) {
    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs_file->fs_info;
    QNX6_INODE ino;
    if (!fs_file || !fs_file->meta) return 1;
    if (qnx6_read_inode(qfs, fs_file->meta->addr, &ino)) return 1;

    uint32_t bs = (uint32_t)qfs->fs_info.block_size;
    uint64_t fsize = tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&ino.size);

    TSK_FS_ATTR *attr = tsk_fs_attrlist_getnew(fs_file->meta->attr, TSK_FS_ATTR_NONRES);
    if (!attr) return 1;

    TSK_FS_ATTR_RUN *head = NULL;
    TSK_FS_ATTR_RUN *tail = NULL;

    uint64_t off = 0;
    TSK_DADDR_T last_addr = 0;
    uint64_t last_off_blocks = 0;

    while (off < fsize) {
        uint32_t ptr = qnx6_ptr_at_offset(qfs, ino.ptr, ino.level, off);
        uint64_t off_blocks = off / bs;

        if (ptr != QNX6_UNUSED_PTR) {
            if (tail && ((TSK_DADDR_T)ptr == last_addr + 1) && (off_blocks == last_off_blocks + 1)) {
                tail->len++;
            } else {
                TSK_FS_ATTR_RUN *r = tsk_fs_attr_run_alloc();
                if (!r) {
                    tsk_fs_attr_run_free(head);
                    return 1;
                }
                r->addr = (TSK_DADDR_T)ptr;
                r->offset = (TSK_DADDR_T)off_blocks;
                r->len = 1;
                r->next = NULL;
                if (!head) head = r;
                else tail->next = r;
                tail = r;
            }
            last_addr = (TSK_DADDR_T)ptr;
            last_off_blocks = off_blocks;
        }
        off += bs;
    }

    /* DEFAULT attribute (non-resident). allocsize: round up to block. */
    TSK_OFF_T allocsize = (TSK_OFF_T)(((fsize + bs - 1) / bs) * bs);

    return tsk_fs_attr_set_run(fs_file, attr, head,
        NULL, TSK_FS_ATTR_TYPE_DEFAULT, 0,
        (TSK_OFF_T)fsize, (TSK_OFF_T)fsize, allocsize,
        TSK_FS_ATTR_FLAG_NONE, 0);
}

static uint8_t qnx6fs_file_add_meta(TSK_FS_INFO *fs, TSK_FS_FILE *fs_file, TSK_INUM_T addr) {
    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs;
    QNX6_INODE ino;

    if (qnx6_read_inode(qfs, addr, &ino)) {
        return 1;
    }

    if (fs_file->meta == NULL) {
        if ((fs_file->meta = tsk_fs_meta_alloc(TSK_FS_META_TAG)) == NULL)
            return 1;
    }

    TSK_FS_META *meta = fs_file->meta;
    tsk_fs_meta_reset(meta);

    meta->addr = addr;
    meta->mode = tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mode);
    meta->uid  = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.uid);
    meta->gid  = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.gid);
    meta->size = (TSK_OFF_T)tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&ino.size);

    meta->mtime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mtime);
    meta->atime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.atime);
    meta->ctime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.ctime);
    meta->crtime = 0;

    /* allocation heuristic */
    if (meta->mode == 0 && meta->size == 0) meta->flags = TSK_FS_META_FLAG_UNALLOC;
    else meta->flags = TSK_FS_META_FLAG_ALLOC;

    meta->type = TSK_FS_META_TYPE_UNDEF;
    uint16_t fmt = meta->mode & S_IFMT;
    if (fmt == S_IFDIR) meta->type = TSK_FS_META_TYPE_DIR;
    else if (fmt == S_IFREG) meta->type = TSK_FS_META_TYPE_REG;
    else if (fmt == S_IFLNK) meta->type = TSK_FS_META_TYPE_LNK;
    else if (fmt == S_IFBLK) meta->type = TSK_FS_META_TYPE_BLK;
    else if (fmt == S_IFCHR) meta->type = TSK_FS_META_TYPE_CHR;
    else if (fmt == S_IFIFO) meta->type = TSK_FS_META_TYPE_FIFO;
    else if (fmt == S_IFSOCK) meta->type = TSK_FS_META_TYPE_SOCK;

    /* attrs are loaded lazily via load_attrs callback */
    return 0;
}

static TSK_RETVAL_ENUM qnx6fs_dir_open_meta(TSK_FS_INFO *fs, TSK_FS_DIR **a_fs_dir, TSK_INUM_T inum, int recursion_depth) {
    (void)recursion_depth;

    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs;
    QNX6_INODE ino;

    if (a_fs_dir == NULL) return TSK_ERR;
    *a_fs_dir = NULL;

    if (qnx6_read_inode(qfs, inum, &ino)) {
        return TSK_ERR;
    }

    uint16_t mode = tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mode);
    if ((mode & S_IFMT) != S_IFDIR) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_dir_open_meta: not a directory");
        return TSK_ERR;
    }

    uint64_t fsize = tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&ino.size);
    if (fsize == 0) {
        *a_fs_dir = tsk_fs_dir_alloc(fs, inum, 4);
        return (*a_fs_dir) ? TSK_OK : TSK_ERR;
    }

    uint32_t got = 0;
    uint8_t *raw = qnx6_read_file_bytes(qfs, ino.ptr, ino.level, fsize, 0, (uint32_t)fsize, &got);
    if (!raw) return TSK_ERR;

    TSK_FS_DIR *dir = tsk_fs_dir_alloc(fs, inum, (size_t)(got / sizeof(QNX6_DIRENT) + 4));
    if (!dir) { free(raw); return TSK_ERR; }

    for (uint64_t off = 0; off + sizeof(QNX6_DIRENT) <= got; off += sizeof(QNX6_DIRENT)) {
        QNX6_DIRENT de;
        memcpy(&de, raw + off, sizeof(de));

        uint32_t child = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&de.inum);
        if (child == 0) continue;

        char *name = NULL;
        uint16_t nlen = 0;

        if (de.length == 0xFF) {
            uint32_t index = tsk_getu32(TSK_LIT_ENDIAN, &de.payload[3]);
            name = qnx6_get_longname(qfs, index, &nlen);
            if (!name) continue;
        } else {
            char shortname[28];
            memset(shortname, 0, sizeof(shortname));
            memcpy(shortname, de.payload, 27);
            nlen = (uint16_t)strlen(shortname);
#ifdef _MSC_VER
            name = _strdup(shortname);
#else
            name = strdup(shortname);
#endif
            if (!name) continue;
        }

        TSK_FS_NAME *fs_name = tsk_fs_name_alloc((size_t)nlen + 1, 0);
        if (!fs_name) { free(name); continue; }

        tsk_fs_name_reset(fs_name);
        strncpy(fs_name->name, name, fs_name->name_size - 1);
        fs_name->name[fs_name->name_size - 1] = '\0';
        fs_name->meta_addr = (TSK_INUM_T)child;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

        /* best-effort type for nicer Autopsy/TSK display */
        {
            QNX6_INODE cino;
            if (qnx6_read_inode(qfs, (TSK_INUM_T)child, &cino) == 0) {
                uint16_t cmode = tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&cino.mode);
                uint16_t cfmt = cmode & S_IFMT;
                if (cfmt == S_IFDIR) fs_name->type = TSK_FS_NAME_TYPE_DIR;
                else if (cfmt == S_IFREG) fs_name->type = TSK_FS_NAME_TYPE_REG;
                else if (cfmt == S_IFLNK) fs_name->type = TSK_FS_NAME_TYPE_LNK;
                else fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
            } else {
                fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
            }
        }

        tsk_fs_dir_add(dir, fs_name);
        /* IMPORTANT: dir owns fs_name now (do NOT free it here) */

        free(name);
    }

    free(raw);
    *a_fs_dir = dir;
    return TSK_OK;
}

static uint8_t qnx6fs_fsstat(TSK_FS_INFO *fs, FILE *hFile) {
    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs;
    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "File System Type: QNX6\n");
    tsk_fprintf(hFile, "Block Size: %u\n", fs->block_size);
    tsk_fprintf(hFile, "Block Count: %" PRIuDADDR "\n", fs->block_count);
    tsk_fprintf(hFile, "Inode Count: %" PRIuINUM "\n", fs->inum_count);
    tsk_fprintf(hFile, "Superblock Serial: %" PRIu64 "\n", (uint64_t)tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&qfs->sb.serial));
    return 0;
}

/* Minimal block walk: treats all blocks as allocated (stable for Autopsy). */
static uint8_t
qnx6fs_block_walk(TSK_FS_INFO* fs, TSK_DADDR_T start, TSK_DADDR_T end,
    TSK_FS_BLOCK_WALK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB cb, void* ptr)
{
    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs;

    if (start < 0) start = 0;
    if (end >= fs->block_count) end = fs->block_count - 1;

    const int aonly = (flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) ? 1 : 0;

    char* buf = NULL;
    if (!aonly) {
        buf = (char*)tsk_malloc((size_t)fs->block_size);
        if (!buf) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
            tsk_error_set_errstr("qnx6fs_block_walk: cannot allocate block buffer");
            return 1;
        }
    }

    for (TSK_DADDR_T blk = start; blk <= end; blk++) {

        // Minimal “Autopsy-ready” behavior:
        // Ohne Bitmap-Analyse behandeln wir erstmal alles als alloc+cont.
        if ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) &&
            !(flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) {
            continue;
        }

        TSK_FS_BLOCK b;
        memset(&b, 0, sizeof(b));
        b.tag = TSK_FS_BLOCK_TAG;
        b.fs_info = fs;
        b.addr = blk;
        b.flags = TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT;
        if (aonly) {
            b.flags |= TSK_FS_BLOCK_FLAG_AONLY;
            b.buf = NULL;
        }
        else {
            b.buf = buf;

            // read actual data
            // Falls du schon qnx6_read_block(qfs, ...) hast, nutze die:
            // if (qnx6_read_block(qfs, (uint32_t)blk, (uint8_t*)buf)) { ... }
            //
            // Minimal: rohe Blockadresse = blk * block_size + data_start
            // (wenn du data_start bereits gesetzt hast)
            TSK_OFF_T off = fs->offset + (TSK_OFF_T)qfs->data_start + (TSK_OFF_T)blk * (TSK_OFF_T)fs->block_size;
            ssize_t r = tsk_img_read(fs->img_info, off, buf, fs->block_size);
            if (r != (ssize_t)fs->block_size) {
                free(buf);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
                tsk_error_set_errstr("qnx6fs_block_walk: cannot read block");
                return 1;
            }

            b.flags |= TSK_FS_BLOCK_FLAG_RAW;
        }

        TSK_WALK_RET_ENUM ret = cb(&b, ptr);
        if (ret == TSK_WALK_STOP) {
            if (buf) free(buf);
            return 0;
        }
        if (ret == TSK_WALK_ERROR) {
            if (buf) free(buf);
            return 1;
        }
    }

    if (buf) free(buf);
    return 0;
}


static uint8_t
qnx6fs_inode_walk(TSK_FS_INFO* fs, TSK_INUM_T start, TSK_INUM_T end,
    TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB cb, void* ptr)
{
    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs;

    if (start < fs->first_inum) start = fs->first_inum;
    if (end > fs->last_inum) end = fs->last_inum;

    for (TSK_INUM_T inum = start; inum <= end; inum++) {

        // Wenn du hier schon “alloc/unalloc” sauber bestimmen willst:
        // qnx6 inode lesen und mode==0 => unalloc
        QNX6_INODE ino;
        int have_inode = (qnx6_read_inode(qfs, inum, &ino) == 0);
        uint16_t mode = have_inode ? tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mode) : 0;
        int is_alloc = (have_inode && mode != 0);

        if ((flags & TSK_FS_META_FLAG_ALLOC) && !is_alloc) continue;
        if ((flags & TSK_FS_META_FLAG_UNALLOC) && is_alloc) continue;

        TSK_FS_FILE* fs_file = tsk_fs_file_alloc(fs);
        if (!fs_file) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
            tsk_error_set_errstr("qnx6fs_inode_walk: cannot allocate fs_file");
            return 1;
        }

        // füllt fs_file->meta (deine Funktion existiert ja schon)
        if (fs->file_add_meta && fs->file_add_meta(fs, fs_file, inum)) {
            tsk_fs_file_close(fs_file);
            continue;
        }

        // Meta-Flags setzen (ALLOC/UNALLOC)
        if (fs_file->meta) {
            fs_file->meta->flags = is_alloc ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC;
            fs_file->meta->type = have_inode ? qnx6_mode_to_meta_type(mode) : TSK_FS_META_TYPE_UNDEF;
        }

        TSK_WALK_RET_ENUM ret = cb(fs_file, ptr);

        tsk_fs_file_close(fs_file);

        if (ret == TSK_WALK_STOP)
            return 0;
        if (ret == TSK_WALK_ERROR)
            return 1;
    }

    return 0;
}


static void qnx6fs_close(TSK_FS_INFO *fs) {
    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs;
    if (!qfs) return;

    tsk_deinit_lock(&qfs->fs_info.list_inum_named_lock);
    tsk_deinit_lock(&qfs->fs_info.orphan_dir_lock);

    /* fs_info is embedded; free only the outer allocation */
    free(qfs);
}

/* ---------------- open ---------------- */

TSK_FS_INFO*
qnx6fs_open(TSK_IMG_INFO* img_info, TSK_OFF_T offset, TSK_FS_TYPE_ENUM fstype, const char* pass, uint8_t test)
{
    (void)pass;

    if (img_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_open: Null image handle");
        return NULL;
    }

    if (fstype != TSK_FS_TYPE_QNX6 && fstype != TSK_FS_TYPE_QNX6_DETECT && fstype != TSK_FS_TYPE_DETECT) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_open: Invalid fstype");
        return NULL;
    }

    QNX6_BOOT boot;
    if (qnx6_read_img(img_info, offset, &boot, sizeof(boot))) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("qnx6fs_open: Cannot read boot block");
        return NULL;
    }

    if (!(boot.magic[0] == 0xEB && boot.magic[1] == 0x10 && boot.magic[2] == 0x90 && boot.magic[3] == 0x00)) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
        tsk_error_set_errstr("qnx6fs_open: Boot magic mismatch");
        return NULL;
    }

    TSK_OFF_T sb0_off = offset + (TSK_OFF_T)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&boot.sblk0) * 512;
    TSK_OFF_T sb1_off = offset + (TSK_OFF_T)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&boot.sblk1) * 512;

    uint8_t raw0[512];
    uint8_t raw1[512];
    if (qnx6_read_img(img_info, sb0_off, raw0, sizeof(raw0)) || qnx6_read_img(img_info, sb1_off, raw1, sizeof(raw1))) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("qnx6fs_open: Cannot read superblocks");
        return NULL;
    }

    int valid0 = (raw0[0] == 0x22 && raw0[1] == 0x11 && raw0[2] == 0x19 && raw0[3] == 0x68);
    int valid1 = (raw1[0] == 0x22 && raw1[1] == 0x11 && raw1[2] == 0x19 && raw1[3] == 0x68);

    if (!valid0 && !valid1) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
        tsk_error_set_errstr("qnx6fs_open: Superblock magic mismatch");
        return NULL;
    }

    uint64_t serial0 = 0, serial1 = 0;
    int ok0 = valid0 ? qnx6_check_superblock_512(raw0, &serial0) : 0;
    int ok1 = valid1 ? qnx6_check_superblock_512(raw1, &serial1) : 0;

    if (!ok0 && !ok1) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("qnx6fs_open: Superblock CRC mismatch");
        return NULL;
    }

    const uint8_t *raw = (ok0 && (!ok1 || serial0 >= serial1)) ? raw0 : raw1;

    QNX6FS_INFO *qfs = (QNX6FS_INFO*)tsk_fs_malloc(sizeof(QNX6FS_INFO));
    if (qfs == NULL) {
        if (test) return NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr("qnx6fs_open: Cannot allocate QNX6FS_INFO");
        return NULL;
    }
    memset(qfs, 0, sizeof(*qfs));

    memcpy(&qfs->sb, raw, sizeof(QNX6_SUPER));

    uint32_t bs = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&qfs->sb.blocksize);
    if (bs == 0 || (bs % 512) != 0) {
        if (test) { free(qfs); return NULL; }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("qnx6fs_open: Invalid block size");
        free(qfs);
        return NULL;
    }

    qfs->data_start = qnx6_data_start(bs);
    qfs->rn_inodes = qfs->sb.inodes;
    qfs->rn_longfile = qfs->sb.longfile;
    qfs->rn_bitmap = qfs->sb.bitmap;

    /* Initialize embedded fs_info */
    qfs->fs_info.tag = TSK_FS_INFO_TAG;
    qfs->fs_info.img_info = img_info;
    qfs->fs_info.offset = offset;
    qfs->fs_info.ftype = TSK_FS_TYPE_QNX6;
    qfs->fs_info.duname = "Block";
    qfs->fs_info.flags = TSK_FS_INFO_FLAG_NONE;
    qfs->fs_info.endian = TSK_LIT_ENDIAN;

    qfs->fs_info.block_size = bs;
    qfs->fs_info.dev_bsize = 512;
    qfs->fs_info.block_count = (TSK_DADDR_T)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&qfs->sb.num_blocks);
    qfs->fs_info.first_block = 0;
    qfs->fs_info.last_block = qfs->fs_info.block_count ? (qfs->fs_info.block_count - 1) : 0;
    qfs->fs_info.last_block_act = qfs->fs_info.last_block;

    qfs->fs_info.inum_count = (TSK_INUM_T)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&qfs->sb.num_inodes);
    qfs->fs_info.root_inum = 1;
    qfs->fs_info.first_inum = 1;
    qfs->fs_info.last_inum = qfs->fs_info.inum_count;

    /* Set function pointers */
    qfs->fs_info.block_walk = qnx6fs_block_walk;
    qfs->fs_info.inode_walk = qnx6fs_inode_walk;
    qfs->fs_info.file_add_meta = qnx6fs_file_add_meta;
    qfs->fs_info.load_attrs = qnx6fs_load_attrs;
    qfs->fs_info.dir_open_meta = qnx6fs_dir_open_meta;
    qfs->fs_info.fsstat = qnx6fs_fsstat;
    qfs->fs_info.close = qnx6fs_close;

    tsk_init_lock(&qfs->fs_info.list_inum_named_lock);
    tsk_init_lock(&qfs->fs_info.orphan_dir_lock);

    /* IMPORTANT: return pointer to embedded TSK_FS_INFO */
    return &qfs->fs_info;
}
