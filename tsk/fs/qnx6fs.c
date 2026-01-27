/*
 * The Sleuth Kit
 * QNX6 file system support (read-only)
 */

#include "tsk_fs_i.h"
#include "qnx6fs.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <string.h>
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

#include "tsk_fs_i.h"   // fr TSK_FS_BLOCK, tsk_fs_block_alloc, tsk_fs_block_set

static TSK_FS_BLOCK_FLAG_ENUM
qnx6fs_block_getflags(TSK_FS_INFO* fs, TSK_DADDR_T addr)
{
    if (fs == NULL) {
        return TSK_FS_BLOCK_FLAG_UNUSED;
    }

    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs;

    /* sehr simple Heuristik:
       - alles vor data_start = META
       - ab data_start = CONT
       - alles als ALLOC markieren (fr icat reicht das zum Lesen)
    */
    TSK_DADDR_T data_start_blk = (TSK_DADDR_T)(qfs->data_start / (uint64_t)fs->block_size);

    if (addr < data_start_blk) {
        return (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_META);
    }
    else {
        return (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT);
    }
}

/* Return the default attribute type for file content.
 * This TSK branch requires fs->get_default_attr_type to be set for icat/tsk_fs_file_walk().
 */
static TSK_FS_ATTR_TYPE_ENUM
qnx6fs_get_default_attr_type(const TSK_FS_FILE *fs_file)
{
    (void)fs_file;
    return TSK_FS_ATTR_TYPE_DEFAULT;
}


static uint8_t
qnx6fs_istat(TSK_FS_INFO* fs, TSK_FS_ISTAT_FLAG_ENUM flags,
    FILE* hFile, TSK_INUM_T inum, TSK_DADDR_T numblock, int32_t sec_skew)
{
    (void)numblock;

    if (fs == NULL || hFile == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_istat: NULL argument");
        return 1;
    }

    TSK_FS_FILE* fs_file = tsk_fs_file_open_meta(fs, NULL, inum);
    if (fs_file == NULL || fs_file->meta == NULL) {
        if (fs_file) tsk_fs_file_close(fs_file);
        return 1;
    }

    TSK_FS_META* meta = fs_file->meta;

    tsk_fprintf(hFile, "Inode: %llu\n", (unsigned long long)inum);
    tsk_fprintf(hFile, "Type: %u\n", (unsigned)meta->type);
    tsk_fprintf(hFile, "Mode: %o\n", (unsigned)meta->mode);
    tsk_fprintf(hFile, "UID / GID: %u / %u\n", (unsigned)meta->uid, (unsigned)meta->gid);
    tsk_fprintf(hFile, "Size: %llu\n", (unsigned long long)meta->size);

    tsk_fprintf(hFile, "MTim: %lld\n", (long long)(meta->mtime + sec_skew));
    tsk_fprintf(hFile, "ATim: %lld\n", (long long)(meta->atime + sec_skew));
    tsk_fprintf(hFile, "CTim: %lld\n", (long long)(meta->ctime + sec_skew));

    if ((flags & TSK_FS_ISTAT_RUNLIST) && meta->attr) {
        /* NOTE: Adjust this call to match YOUR tsk_fs_attrlist_get() signature */
        const TSK_FS_ATTR* attr = tsk_fs_attrlist_get(meta->attr, TSK_FS_ATTR_TYPE_DEFAULT);
        /* If your signature is (attrlist, type) use:
         * const TSK_FS_ATTR *attr = tsk_fs_attrlist_get(meta->attr, TSK_FS_ATTR_TYPE_DEFAULT);
         */

        if (attr && (attr->flags & TSK_FS_ATTR_NONRES) && attr->nrd.run) {
            tsk_fprintf(hFile, "\nData Runs:\n");
            const TSK_FS_ATTR_RUN* run = attr->nrd.run;
            while (run) {
                if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE) {
                    tsk_fprintf(hFile, "  off=%" PRIuDADDR " len=%" PRIuDADDR " SPARSE\n",
                        run->offset, run->len);
                }
                else {
                    tsk_fprintf(hFile, "  off=%" PRIuDADDR " addr=%" PRIuDADDR " len=%" PRIuDADDR "\n",
                        run->offset, run->addr, run->len);
                }
                run = run->next;
            }
        }
    }

    tsk_fs_file_close(fs_file);
    return 0;
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
    TSK_OFF_T off = qfs->fs_info.offset + (TSK_OFF_T)qfs->data_start + (TSK_OFF_T)blk * qfs->fs_info.block_size;
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

static uint8_t
qnx6fs_load_attrs(TSK_FS_FILE* fs_file)
{
    if (fs_file == NULL || fs_file->fs_info == NULL || fs_file->meta == NULL) {
        return 1;
    }

    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs_file->fs_info;

    QNX6_INODE ino;
    if (qnx6_read_inode(qfs, fs_file->meta->addr, &ino)) {
        return 1;
    }

    uint32_t bs = (uint32_t)qfs->fs_info.block_size;
    uint64_t fsize = tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&ino.size);

    /* Allocate attrlist lazily (icat expects this to be done here). */
    if (fs_file->meta->attr == NULL) {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
        if (fs_file->meta->attr == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
            tsk_error_set_errstr("qnx6fs_load_attrs: cannot allocate attrlist");
            return 1;
        }
    }

    /* Create a new NONRES attribute entry */
    TSK_FS_ATTR* attr = tsk_fs_attrlist_getnew(fs_file->meta->attr, TSK_FS_ATTR_NONRES);
    if (attr == NULL) {
        return 1;
    }

    TSK_FS_ATTR_RUN* head = NULL;
    TSK_FS_ATTR_RUN* tail = NULL;

    const TSK_DADDR_T data_start_blk = (TSK_DADDR_T)(qfs->data_start / (uint64_t)bs);

    uint64_t off = 0;
    int have_last = 0;
    TSK_DADDR_T last_addr = 0;
    TSK_DADDR_T last_off_blk = 0;

    while (off < fsize) {
        uint32_t ptr = qnx6_ptr_at_offset(qfs, ino.ptr, ino.level, off);
        TSK_DADDR_T off_blk = (TSK_DADDR_T)(off / bs);

        if (ptr != QNX6_UNUSED_PTR) {
            TSK_DADDR_T addr = (TSK_DADDR_T)ptr + data_start_blk;

            if (have_last && tail && (addr == last_addr + 1) && (off_blk == last_off_blk + 1)) {
                tail->len++;
            }
            else {
                TSK_FS_ATTR_RUN* r = tsk_fs_attr_run_alloc();
                if (r == NULL) {
                    tsk_fs_attr_run_free(head);
                    return 1;
                }

                /* IMPORTANT: initialize fully */
                memset(r, 0, sizeof(*r));
                r->addr = addr;
                r->offset = off_blk;
                r->len = 1;
                r->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
                r->crypto_id = 0;
                r->next = NULL;

                if (head == NULL) head = r;
                else tail->next = r;
                tail = r;
            }

            have_last = 1;
            last_addr = addr;
            last_off_blk = off_blk;
        }

        off += bs;
    }

    TSK_OFF_T size = (TSK_OFF_T)fsize;
    TSK_OFF_T allocsize = (TSK_OFF_T)(((fsize + bs - 1) / bs) * bs);

    /*
     * This call wires runlist into attr->nrd and sets sizes.
     * For your branch: MUST pass TSK_FS_ATTR_NONRES as flags,
     * otherwise the attribute may not be treated as non-resident.
     */
    if (tsk_fs_attr_set_run(fs_file, attr, head,
        NULL, TSK_FS_ATTR_TYPE_DEFAULT, 0,
        size, size, allocsize,
        TSK_FS_ATTR_NONRES, 0)) {
        /* on failure, avoid leaking runlist */
        tsk_fs_attr_run_free(head);
        return 1;
    }

    return 0;
}


static uint8_t
qnx6fs_file_add_meta(TSK_FS_INFO* fs, TSK_FS_FILE* fs_file, TSK_INUM_T addr)
{
    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs;
    QNX6_INODE ino;

    if (fs == NULL || fs_file == NULL) {
        return 1;
    }

    if (qnx6_read_inode(qfs, addr, &ino)) {
        return 1;
    }

    if (fs_file->meta == NULL) {
        fs_file->meta = tsk_fs_meta_alloc(TSK_FS_META_TAG);
        if (fs_file->meta == NULL) {
            return 1;
        }
    }

    TSK_FS_META* meta = fs_file->meta;
    tsk_fs_meta_reset(meta);

    meta->addr = addr;
    meta->mode = tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mode);
    meta->uid = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.uid);
    meta->gid = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.gid);
    meta->size = (TSK_OFF_T)tsk_getu64(TSK_LIT_ENDIAN, (const uint8_t*)&ino.size);

    meta->mtime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mtime);
    meta->atime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.atime);
    meta->ctime = (time_t)tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&ino.ctime);
    meta->crtime = 0;

    meta->flags = TSK_FS_META_FLAG_ALLOC;

    /* Meta-Type aus POSIX mode ableiten */
    meta->type = TSK_FS_META_TYPE_UNDEF;
    {
        uint16_t fmt = meta->mode & S_IFMT;
        if (fmt == S_IFDIR) meta->type = TSK_FS_META_TYPE_DIR;
        else if (fmt == S_IFREG) meta->type = TSK_FS_META_TYPE_REG;
        else if (fmt == S_IFLNK) meta->type = TSK_FS_META_TYPE_LNK;
        else if (fmt == S_IFBLK) meta->type = TSK_FS_META_TYPE_BLK;
        else if (fmt == S_IFCHR) meta->type = TSK_FS_META_TYPE_CHR;
        else if (fmt == S_IFIFO) meta->type = TSK_FS_META_TYPE_FIFO;
        else if (fmt == S_IFSOCK) meta->type = TSK_FS_META_TYPE_SOCK;
    }

    /*
     * WICHTIG:
     * meta->attr hier NICHT anlegen.
     * icat/tsk_fs_file_walk() triggert load_attrs() nur wenn meta->attr == NULL.
     */
    meta->attr = NULL;

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

        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(nlen + 1, 0);
        if (!fs_name) { free(name); continue; }

        tsk_fs_name_reset(fs_name);
        strncpy(fs_name->name, name, fs_name->name_size - 1);
        fs_name->meta_addr = (TSK_INUM_T)child;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

        tsk_fs_dir_add(dir, fs_name);
        tsk_fs_name_free(fs_name);
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

#include "tsk/fs/tsk_fs_i.h"   // f�r tsk_fs_block_alloc/free + tsk_malloc (je nach Layout)


static uint8_t
qnx6fs_block_walk(TSK_FS_INFO* fs,
    TSK_DADDR_T start,
    TSK_DADDR_T end,
    TSK_FS_BLOCK_WALK_FLAG_ENUM flags,
    TSK_FS_BLOCK_WALK_CB cb,
    void* ptr)
{
    if (fs == NULL || cb == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_block_walk: NULL argument");
        return 1;
    }

    /* clamp range */
    if (start < fs->first_block)
        start = fs->first_block;
    if (end > fs->last_block)
        end = fs->last_block;
    if (start > end)
        return 0;

    TSK_FS_BLOCK* fs_block = tsk_fs_block_alloc(fs);
    if (fs_block == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr("qnx6fs_block_walk: cannot allocate TSK_FS_BLOCK");
        return 1;
    }

    for (TSK_DADDR_T addr = start; addr <= end; addr++) {

        TSK_FS_BLOCK_FLAG_ENUM blk_flags = qnx6fs_block_getflags(fs, addr);

        /* if caller only wants alloc/unalloc filtering */
        if ((flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) && !(blk_flags & TSK_FS_BLOCK_FLAG_ALLOC))
            continue;
        if ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) && (blk_flags & TSK_FS_BLOCK_FLAG_ALLOC))
            continue;

        /* AONLY: don't read content */
        if (flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) {
            TSK_FS_BLOCK_FLAG_ENUM out_flags = (TSK_FS_BLOCK_FLAG_ENUM)(blk_flags | TSK_FS_BLOCK_FLAG_AONLY);
            tsk_fs_block_set(fs, fs_block, addr, out_flags, NULL);

            if (cb(fs_block, ptr)) {
                tsk_fs_block_free(fs_block);
                return 1;
            }
            continue;
        }

        /* read block content */
        TSK_OFF_T off = fs->offset + (TSK_OFF_T)addr * (TSK_OFF_T)fs->block_size;
        ssize_t r = tsk_img_read(fs->img_info, off, (char*)fs_block->buf, fs->block_size);
        if (r != (ssize_t)fs->block_size) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
            tsk_error_set_errstr("qnx6fs_block_walk: cannot read block");
            /* avoid PRIuOFF trouble */
            tsk_error_set_errstr2("block=%" PRIuDADDR " off=%llu",
                addr, (unsigned long long)off);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        /* mark buffer as valid raw content */
        TSK_FS_BLOCK_FLAG_ENUM out_flags = (TSK_FS_BLOCK_FLAG_ENUM)(blk_flags | TSK_FS_BLOCK_FLAG_RAW);
        tsk_fs_block_set(fs, fs_block, addr, out_flags, (char*)fs_block->buf);

        if (cb(fs_block, ptr)) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    tsk_fs_block_free(fs_block);
    return 0;
}

static uint8_t
qnx6fs_inode_walk(TSK_FS_INFO* fs, TSK_INUM_T start, TSK_INUM_T end,
    TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB cb, void* ptr)
{
    if (fs == NULL || cb == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6fs_inode_walk: NULL argument");
        return 1;
    }

    QNX6FS_INFO* qfs = (QNX6FS_INFO*)fs;

    /* Clamp range */
    if (start < fs->first_inum) start = fs->first_inum;
    if (end > fs->last_inum) end = fs->last_inum;
    if (start > end) return 0;

    for (TSK_INUM_T inum = start; inum <= end; inum++) {

        /* Read inode first to decide alloc/unalloc quickly */
        QNX6_INODE ino;
        if (qnx6_read_inode(qfs, inum, &ino)) {
            /* unreadable inode -> treat as skip (or could report UNALLOC) */
            continue;
        }

        /* Simple allocation heuristic:
           - if mode == 0 -> unalloc
           - else alloc
           (Wenn du ein besseres Bit/Flag im inode hast, hier ersetzen!)
        */
        uint16_t mode = tsk_getu16(TSK_LIT_ENDIAN, (const uint8_t*)&ino.mode);
        uint8_t is_alloc = (mode != 0);

        /* Apply requested flags (best-effort, like other FS drivers) */
        if (is_alloc) {
            if ((flags & TSK_FS_META_FLAG_UNALLOC) && !(flags & TSK_FS_META_FLAG_ALLOC)) {
                continue;
            }
        }
        else {
            if ((flags & TSK_FS_META_FLAG_ALLOC) && !(flags & TSK_FS_META_FLAG_UNALLOC)) {
                continue;
            }
        }

        /* Build a TSK_FS_FILE for callback */
        TSK_FS_FILE* fs_file = tsk_fs_file_alloc(fs);
        if (fs_file == NULL) {
            return 1;
        }

        /* Populate meta via driver hook */
        if (fs->file_add_meta) {
            if (fs->file_add_meta(fs, fs_file, inum)) {
                tsk_fs_file_close(fs_file);
                continue;
            }
        }
        else {
            tsk_fs_file_close(fs_file);
            continue;
        }

        /* Ensure alloc/unalloc is consistent with our heuristic */
        if (fs_file->meta) {
            if (is_alloc)
                fs_file->meta->flags = (TSK_FS_META_FLAG_ENUM)(fs_file->meta->flags | TSK_FS_META_FLAG_ALLOC);
            else
                fs_file->meta->flags = (TSK_FS_META_FLAG_ENUM)(fs_file->meta->flags | TSK_FS_META_FLAG_UNALLOC);
        }

        /* Callback */
        if (cb(fs_file, ptr)) {
            tsk_fs_file_close(fs_file);
            return 1;
        }

        tsk_fs_file_close(fs_file);
    }

    return 0;
}


static void qnx6fs_close(TSK_FS_INFO *fs) {
    if (fs == NULL) return;
    /* fs points to the start of QNX6FS_INFO because fs_info is the first field */
    QNX6FS_INFO *qfs = (QNX6FS_INFO*)fs;

    tsk_deinit_lock(&qfs->fs_info.list_inum_named_lock);
    tsk_deinit_lock(&qfs->fs_info.orphan_dir_lock);

    /* tsk_fs_free() will free the structure it is passed (which is qfs). */
    tsk_fs_free(fs);
}

static uint8_t qnx6fs_istat(TSK_FS_INFO* fs, TSK_FS_ISTAT_FLAG_ENUM flags,
    FILE* hFile, TSK_INUM_T inum, TSK_DADDR_T numblock, int32_t sec_skew);


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

    uint32_t sblk0 = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&boot.sblk0);
uint32_t sblk1 = tsk_getu32(TSK_LIT_ENDIAN, (const uint8_t*)&boot.sblk1);

/* Superblock is stored in a fixed 0x1000-byte area, independent of FS blocksize.
 * Most images use 512-byte units for sblk0/sblk1, but some vendors store it in
 * (blocksize/2) units (e.g., blocksize=2048 -> unit=1024). We therefore probe
 * several plausible multipliers and then validate via magic + CRC. */
static const uint32_t sb_mults[] = { 512, 1024, 2048, 4096, 8192 };

uint8_t raw0[512];
uint8_t raw1[512];
memset(raw0, 0, sizeof(raw0));
memset(raw1, 0, sizeof(raw1));

TSK_OFF_T sb0_off = 0, sb1_off = 0;
int have0 = 0, have1 = 0;

for (size_t i = 0; i < sizeof(sb_mults)/sizeof(sb_mults[0]); i++) {
    if (!have0) {
        TSK_OFF_T off = offset + (TSK_OFF_T)sblk0 * (TSK_OFF_T)sb_mults[i];
        if (qnx6_read_img(img_info, off, raw0, sizeof(raw0)) == 0) {
            if (raw0[0] == 0x22 && raw0[1] == 0x11 && raw0[2] == 0x19 && raw0[3] == 0x68) {
                have0 = 1;
                sb0_off = off;
            }
        }
    }
    if (!have1) {
        TSK_OFF_T off = offset + (TSK_OFF_T)sblk1 * (TSK_OFF_T)sb_mults[i];
        if (qnx6_read_img(img_info, off, raw1, sizeof(raw1)) == 0) {
            if (raw1[0] == 0x22 && raw1[1] == 0x11 && raw1[2] == 0x19 && raw1[3] == 0x68) {
                have1 = 1;
                sb1_off = off;
            }
        }
    }
    if (have0 && have1) break;
}

/* Fallbacks seen in the wild: superblock starts at byte 0 or at 0x2000 (bootblock size). */
if (!have0) {
    TSK_OFF_T off = offset;
    if (qnx6_read_img(img_info, off, raw0, sizeof(raw0)) == 0 &&
        raw0[0] == 0x22 && raw0[1] == 0x11 && raw0[2] == 0x19 && raw0[3] == 0x68) {
        have0 = 1;
        sb0_off = off;
    }
}
if (!have0) {
    TSK_OFF_T off = offset + 0x2000;
    if (qnx6_read_img(img_info, off, raw0, sizeof(raw0)) == 0 &&
        raw0[0] == 0x22 && raw0[1] == 0x11 && raw0[2] == 0x19 && raw0[3] == 0x68) {
        have0 = 1;
        sb0_off = off;
    }
}
if (!have1) {
    TSK_OFF_T off = offset;
    if (qnx6_read_img(img_info, off, raw1, sizeof(raw1)) == 0 &&
        raw1[0] == 0x22 && raw1[1] == 0x11 && raw1[2] == 0x19 && raw1[3] == 0x68) {
        have1 = 1;
        sb1_off = off;
    }
}
if (!have1) {
    TSK_OFF_T off = offset + 0x2000;
    if (qnx6_read_img(img_info, off, raw1, sizeof(raw1)) == 0 &&
        raw1[0] == 0x22 && raw1[1] == 0x11 && raw1[2] == 0x19 && raw1[3] == 0x68) {
        have1 = 1;
        sb1_off = off;
    }
}

int valid0 = have0;
int valid1 = have1;

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
        // Older/newer TSK branches use different error codes for allocation
        // failures. TSK_ERR_AUX_MALLOC is widely supported.
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

    // Initialize embedded fs_info
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

    // Set function pointers
    qfs->fs_info.block_walk = qnx6fs_block_walk;
    qfs->fs_info.block_getflags = qnx6fs_block_getflags;
    qfs->fs_info.inode_walk = qnx6fs_inode_walk;
    qfs->fs_info.file_add_meta = qnx6fs_file_add_meta;
    qfs->fs_info.load_attrs = qnx6fs_load_attrs;
    qfs->fs_info.dir_open_meta = qnx6fs_dir_open_meta;
    qfs->fs_info.fsstat = qnx6fs_fsstat;
    qfs->fs_info.get_default_attr_type = qnx6fs_get_default_attr_type;
    qfs->fs_info.istat = qnx6fs_istat;
    qfs->fs_info.close = qnx6fs_close;

    tsk_init_lock(&qfs->fs_info.list_inum_named_lock);
    tsk_init_lock(&qfs->fs_info.orphan_dir_lock);

    return (TSK_FS_INFO*)qfs;
}
