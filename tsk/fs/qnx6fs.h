#ifndef _TSK_QNX6FS_H
#define _TSK_QNX6FS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "tsk_fs.h"

struct TSK_IMG_INFO;
typedef struct TSK_IMG_INFO TSK_IMG_INFO;

TSK_FS_INFO *qnx6fs_open(TSK_IMG_INFO *img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM fstype, const char *pass, uint8_t test);

#ifdef __cplusplus
}
#endif

#endif
