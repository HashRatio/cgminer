/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2014 Xiangfu <xiangfu@openmobilefree.com>
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include <windows.h>
  #include <io.h>
#endif

#include "elist.h"
#include "miner.h"
#include "fpgautils.h"
#include "driver-hashratio.h"
#include "crc.h"
#include "hexdump.c"

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);

int opt_hashratio_fan_min = HRTO_DEFAULT_FAN_PWM;
int opt_hashratio_fan_max = HRTO_DEFAULT_FAN_MAX;

static int hashratio_read(struct cgpu_info *hashratio, char *buf, size_t bufsize, int ep);
static int hashratio_write(struct cgpu_info *hashratio, char *buf, ssize_t len, int ep);
static void hashratio_initialise(struct cgpu_info *hashratio);

static inline uint8_t rev8(uint8_t d)
{
    int i;
    uint8_t out = 0;

    /* (from left to right) */
    for (i = 0; i < 8; i++)
        if (d & (1 << i))
            out |= (1 << (7 - i));

    return out;
}

char *set_hashratio_fan(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No values passed to hashratio-fan";
	if (ret == 1)
		val2 = val1;

	if (val1 < 0 || val1 > 100 || val2 < 0 || val2 > 100 || val2 < val1)
		return "Invalid value passed to hashratio-fan";

	opt_hashratio_fan_min = HRTO_PWM_MAX - val1 * HRTO_PWM_MAX / 100;
	opt_hashratio_fan_max = HRTO_PWM_MAX - val2 * HRTO_PWM_MAX / 100;

	return NULL;
}

static int hashratio_init_pkg(struct hashratio_pkg *pkg, uint8_t type,
							  uint8_t idx, uint8_t cnt)
{
	unsigned short crc;

	pkg->head[0] = HRTO_H1;
	pkg->head[1] = HRTO_H2;

	pkg->type = type;
	pkg->idx = idx;
	pkg->cnt = cnt;

	crc = crc16(pkg->data, HRTO_P_DATA_LEN);

	pkg->crc[0] = (crc & 0xff00) >> 8;
	pkg->crc[1] = crc & 0x00ff;
	return 0;
}

static int job_idcmp(uint8_t *job_id, char *pool_job_id)
{
	int i = 0;
	for (i = 0; i < 4; i++) {
		if (job_id[i] != *(pool_job_id + strlen(pool_job_id) - 4 + i))
			return 1;
	}
	return 0;
}

static inline int get_temp_max(struct hashratio_info *info)
{
	int i;
//	for (i = 0; i < 2 * HRTO_DEFAULT_MODULARS; i++) {
//		if (info->temp_max <= info->temp[i])
//			info->temp_max = info->temp[i];
//	}
//	for (i = 0; i < 2 * HRTO_DEFAULT_MODULARS; i++) {
//		if (info->temp_max <= info->temp[i])
//			info->temp_max = info->temp[i];
//	}
	if (info->temp_max < info->temp) {
		info->temp_max = info->temp;
	}
	return info->temp_max;
}

extern void submit_nonce2_nonce(struct thr_info *thr, uint32_t pool_no, uint32_t nonce2, uint32_t nonce);
static int decode_pkg(struct thr_info *thr, struct hashratio_ret *ar, uint8_t *pkg)
{
	struct cgpu_info *hashratio;
	struct hashratio_info *info;
	struct pool *pool;

	unsigned int expected_crc;
	unsigned int actual_crc;
	uint32_t nonce, nonce2, miner, modular_id;
	int pool_no;
	uint8_t job_id[5];
	int tmp;

	int type = HRTO_GETS_ERROR;
	
	if (thr) {
		hashratio = thr->cgpu;
		info = hashratio->device_data;
	} else // FIXME: Should this happen at all!?
		return 0;

	memcpy((uint8_t *)ar, pkg, HRTO_READ_SIZE);

	if (ar->head[0] != HRTO_H1 || ar->head[1] != HRTO_H2) {
		return HRTO_GETS_ERROR;
	}
	
	expected_crc = crc16(ar->data, HRTO_P_DATA_LEN);
	actual_crc = (ar->crc[0] & 0xff) |
		((ar->crc[1] & 0xff) << 8);

	type = ar->type;
	applog(LOG_DEBUG, "Hashratio: %d: expected crc(%04x), actural_crc(%04x)",
		   type, expected_crc, actual_crc);
	if (expected_crc != actual_crc)
		goto out;

//	memcpy(&modular_id, ar->data + 28, 4);
//	modular_id = be32toh(modular_id);
//	if (modular_id == 3)
//		modular_id = 0;

	switch(type) {
	case HRTO_P_NONCE:
		memcpy(&miner,   ar->data + 0, 4);
		memcpy(&pool_no, ar->data + 4, 4);
		memcpy(&nonce2,  ar->data + 8, 4);
		/* Calc time    ar->data + 12 */
		memcpy(&nonce,   ar->data + 16, 4);
		memset(job_id,   0,             5);
		memcpy(job_id,   ar->data + 20, 4);

		miner   = be32toh(miner);
		pool_no = be32toh(pool_no);
//		if (miner >= HRTO_DEFAULT_MINERS || modular_id >= HRTO_DEFAULT_MODULARS ||
//			pool_no >= total_pools || pool_no < 0) {
//			applog(LOG_DEBUG, "Hashratio: Wrong miner/pool/id no %d,%d,%d",
//				   miner, pool_no, modular_id);
//			break;
//		} else {
//			info->matching_work[modular_id * HRTO_DEFAULT_MINERS + miner]++;
//		}
		if (miner >= HRTO_DEFAULT_MINERS || pool_no >= total_pools || pool_no < 0) {
			applog(LOG_DEBUG, "Hashratio: Wrong miner/pool/id no %d,%d",
				   miner, pool_no);
			break;
		} else {
			info->matching_work[miner]++;
		}
		nonce2 = be32toh(nonce2);
		nonce  = be32toh(nonce);
//		nonce -= 0x180;

		applog(LOG_DEBUG, "Hashratio: Found! [%s] %d:(%08x) (%08x)",
			   job_id, pool_no, nonce2, nonce);
		/* FIXME:
		 * We need remember the pre_pool. then submit the stale work */
		pool = pools[pool_no];
		if (job_idcmp(job_id, pool->swork.job_id)) { break; }

		if (thr && !info->new_stratum) {
			submit_nonce2_nonce(thr, pool_no, nonce2, nonce);
		}
		break;
	case HRTO_P_STATUS:
		memcpy(&tmp, ar->data, 4);
		info->temp = be32toh(tmp);
//		tmp = be32toh(tmp);
//		info->temp[0 + modular_id * 2] = tmp >> 16;
//		info->temp[1 + modular_id * 2] = tmp & 0xffff;

		memcpy(&tmp, ar->data + 4, 4);
		info->fan = be32toh(tmp);
//		tmp = be32toh(tmp);
//		info->fan[0 + modular_id * 2] = tmp >> 16;
//		info->fan[1 + modular_id * 2] = tmp & 0xffff;

//		memcpy(&(info->get_frequency[modular_id]), ar->data + 8, 4);
//		memcpy(&(info->get_voltage[modular_id]), ar->data + 12, 4);
//		memcpy(&(info->local_work[modular_id]), ar->data + 16, 4);
//		memcpy(&(info->hw_work[modular_id]),    ar->data + 20, 4);
		memcpy(&(info->local_work), ar->data + 16, 4);
		memcpy(&(info->hw_work),    ar->data + 20, 4);

//		info->get_frequency[modular_id] = be32toh(info->get_frequency[modular_id]);
//		info->get_voltage  [modular_id] = be32toh(info->get_voltage[modular_id]);
//		info->local_work   [modular_id] = be32toh(info->local_work[modular_id]);
//		info->hw_work      [modular_id] = be32toh(info->hw_work[modular_id]);
		info->local_work = be32toh(info->local_work);
		info->hw_work    = be32toh(info->hw_work);

//		info->local_works[modular_id] += info->local_work[modular_id];
//		info->hw_works   [modular_id] += info->hw_work[modular_id];
		info->local_works += info->local_work;
		info->hw_works    += info->hw_work;


//		info->get_voltage[modular_id] = decode_voltage(info->get_voltage[modular_id]);
		hashratio->temp = get_temp_max(info);
		break;
	case HRTO_P_ACKDETECT:
		break;
	case HRTO_P_ACK:
		break;
	case HRTO_P_NAK:
		break;
	default:
		type = HRTO_GETS_ERROR;
		break;
	}

out:
	return type;
}

//static inline int hashratio_gets(int fd, uint8_t *buf)
//{
//	int i;
//	int read_amount = HRTO_READ_SIZE;
//	uint8_t buf_tmp[HRTO_READ_SIZE];
//	uint8_t buf_copy[2 * HRTO_READ_SIZE];
//	uint8_t *buf_back = buf;
//	ssize_t ret = 0;
//
//	while (true) {
//		struct timeval timeout;
//		fd_set rd;
//
//		timeout.tv_sec  = 0;
//		timeout.tv_usec = 100000;
//
//		FD_ZERO(&rd);
//		FD_SET(fd, &rd);
//		ret = select(fd + 1, &rd, NULL, NULL, &timeout);
//		if (unlikely(ret < 0)) {
//			applog(LOG_ERR, "Hashratio: Error %d on select in hashratio_gets", errno);
//			return HRTO_GETS_ERROR;
//		}
//		if (ret) {
//			memset(buf, 0, read_amount);
//			ret = read(fd, buf, read_amount);
//			if (unlikely(ret < 0)) {
//				applog(LOG_ERR, "Hashratio: Error %d on read in hashratio_gets", errno);
//				return HRTO_GETS_ERROR;
//			}
//			if (likely(ret >= read_amount)) {
//				for (i = 1; i < read_amount; i++) {
//					if (buf_back[i - 1] == HRTO_H1 && buf_back[i] == HRTO_H2)
//						break;
//				}
//				i -= 1;
//				if (i) {
//					ret = read(fd, buf_tmp, i);
//					if (unlikely(ret != i)) {
//						applog(LOG_ERR, "Hashratio: Error %d on read in hashratio_gets", errno);
//						return HRTO_GETS_ERROR;
//					}
//					memcpy(buf_copy, buf_back + i, HRTO_READ_SIZE - i);
//					memcpy(buf_copy + HRTO_READ_SIZE - i, buf_tmp, i);
//					memcpy(buf_back, buf_copy, HRTO_READ_SIZE);
//				}
//				return HRTO_GETS_OK;
//			}
//			buf += ret;
//			read_amount -= ret;
//			continue;
//		}
//
//		return HRTO_GETS_TIMEOUT;
//	}
//}

static int hashratio_send_pkg(const struct hashratio_pkg *pkg,
							  struct thr_info __maybe_unused *thr)
{
	int ret;
	uint8_t buf[HRTO_WRITE_SIZE];
	int nr_len = HRTO_WRITE_SIZE;
	struct cgpu_info *hashratio = thr->cgpu;
	
	memcpy(buf, pkg, HRTO_WRITE_SIZE);
	if (opt_debug) {
		applog(LOG_DEBUG, "Hashratio: Sent(%d):", nr_len);
		hexdump((uint8_t *)buf, nr_len);
	}
	
//	static int hashratio_write(struct cgpu_info *hashratio, char *buf, ssize_t len, int ep)
	
	ret = hashratio_write(hashratio, buf, nr_len, C_HASHRATIO_PKG);
	if (unlikely(ret != nr_len)) {
		applog(LOG_DEBUG, "Hashratio: Send(%d)!", ret);
		return HRTO_SEND_ERROR;
	}
	
	cgsleep_ms(20);
	
#if 0
//	ret = hashratio_gets(fd, result);
//	ret = hashratio_read(hashratio, BUFSI, size_t bufsize, int ep)
//	if (ret != HRTO_GETS_OK) {
//		applog(LOG_DEBUG, "Hashratio: Get(%d)!", ret);
//		return HRTO_SEND_ERROR;
//	}
//	
//	ret = decode_pkg(thr, &ar, result);
//	if (ret != HRTO_P_ACK) {
//		applog(LOG_DEBUG, "Hashratio: PKG(%d)!", ret);
//		hexdump((uint8_t *)result, HRTO_READ_SIZE);
//		return HRTO_SEND_ERROR;
//	}
#endif
	
	return HRTO_SEND_OK;
}

//static int hashratio_send_pkg(int fd, const struct hashratio_pkg *pkg,
//							  struct thr_info __maybe_unused *thr)
//{
//	int ret;
//	uint8_t buf[HRTO_WRITE_SIZE];
//	int nr_len = HRTO_WRITE_SIZE;
//
//	memcpy(buf, pkg, HRTO_WRITE_SIZE);
//	if (opt_debug) {
//		applog(LOG_DEBUG, "Hashratio: Sent(%d):", nr_len);
//		hexdump((uint8_t *)buf, nr_len);
//	}
//
//	ret = write(fd, buf, nr_len);
//	if (unlikely(ret != nr_len)) {
//		applog(LOG_DEBUG, "Hashratio: Send(%d)!", ret);
//		return HRTO_SEND_ERROR;
//	}
//
//	cgsleep_ms(20);
//#if 0
//	ret = hashratio_gets(fd, result);
//	if (ret != HRTO_GETS_OK) {
//		applog(LOG_DEBUG, "Hashratio: Get(%d)!", ret);
//		return HRTO_SEND_ERROR;
//	}
//
//	ret = decode_pkg(thr, &ar, result);
//	if (ret != HRTO_P_ACK) {
//		applog(LOG_DEBUG, "Hashratio: PKG(%d)!", ret);
//		hexdump((uint8_t *)result, HRTO_READ_SIZE);
//		return HRTO_SEND_ERROR;
//	}
//#endif
//
//	return HRTO_SEND_OK;
//}

static int hashratio_stratum_pkgs(struct pool *pool, struct thr_info *thr)
{
	const int merkle_offset = 36;
	struct hashratio_pkg pkg;
	int i, a, b, tmp;
	unsigned char target[32];
	int job_id_len;
//	struct cgpu_info *hashratio = thr->cgpu;

	/* Send out the first stratum message STATIC */
	applog(LOG_DEBUG, "Hashratio: Pool stratum message STATIC: %d, %d, %d, %d, %d",
	       pool->coinbase_len,
	       pool->nonce2_offset,
	       pool->n2size,
	       merkle_offset,
	       pool->merkles);
	memset(pkg.data, 0, HRTO_P_DATA_LEN);
	tmp = be32toh(pool->coinbase_len);
	memcpy(pkg.data, &tmp, 4);

	tmp = be32toh(pool->nonce2_offset);
	memcpy(pkg.data + 4, &tmp, 4);

	tmp = be32toh(pool->n2size);
	memcpy(pkg.data + 8, &tmp, 4);

	tmp = be32toh(merkle_offset);
	memcpy(pkg.data + 12, &tmp, 4);

	tmp = be32toh(pool->merkles);
	memcpy(pkg.data + 16, &tmp, 4);

	tmp = be32toh((int32_t)pool->swork.diff);
	memcpy(pkg.data + 20, &tmp, 4);

	tmp = be32toh((int32_t)pool->pool_no);
	memcpy(pkg.data + 24, &tmp, 4);

	hashratio_init_pkg(&pkg, HRTO_P_STATIC, 1, 1);
	while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
		;

	set_target(target, pool->swork.diff);
	memcpy(pkg.data, target, 32);
	if (opt_debug) {
		char *target_str;
		target_str = bin2hex(target, 32);
		applog(LOG_DEBUG, "Hashratio: Pool stratum target: %s", target_str);
		free(target_str);
	}
	hashratio_init_pkg(&pkg, HRTO_P_TARGET, 1, 1);
	while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
		;


	applog(LOG_DEBUG, "Hashratio: Pool stratum message JOBS_ID: %s",
	       pool->swork.job_id);
	memset(pkg.data, 0, HRTO_P_DATA_LEN);

	job_id_len = strlen(pool->swork.job_id);
	job_id_len = job_id_len >= 4 ? 4 : job_id_len;
	for (i = 0; i < job_id_len; i++) {
		pkg.data[i] = *(pool->swork.job_id + strlen(pool->swork.job_id) - 4 + i);
	}
	hashratio_init_pkg(&pkg, HRTO_P_JOB_ID, 1, 1);
	while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
		;

	a = pool->coinbase_len / HRTO_P_DATA_LEN;
	b = pool->coinbase_len % HRTO_P_DATA_LEN;
	applog(LOG_DEBUG, "Hashratio: Pool stratum message COINBASE: %d %d", a, b);
	for (i = 0; i < a; i++) {
		memcpy(pkg.data, pool->coinbase + i * 32, 32);
		hashratio_init_pkg(&pkg, HRTO_P_COINBASE, i + 1, a + (b ? 1 : 0));
		while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
			;
	}
	if (b) {
		memset(pkg.data, 0, HRTO_P_DATA_LEN);
		memcpy(pkg.data, pool->coinbase + i * 32, b);
		hashratio_init_pkg(&pkg, HRTO_P_COINBASE, i + 1, i + 1);
		while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
			;
	}

	b = pool->merkles;
	applog(LOG_DEBUG, "Hashratio: Pool stratum message MERKLES: %d", b);
	for (i = 0; i < b; i++) {
		memset(pkg.data, 0, HRTO_P_DATA_LEN);
		memcpy(pkg.data, pool->swork.merkle_bin[i], 32);
		hashratio_init_pkg(&pkg, HRTO_P_MERKLES, i + 1, b);
		while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
			;
	}

	applog(LOG_DEBUG, "Hashratio: Pool stratum message HEADER: 4");
	for (i = 0; i < 4; i++) {
		memset(pkg.data, 0, HRTO_P_HEADER);
		memcpy(pkg.data, pool->header_bin + i * 32, 32);
		hashratio_init_pkg(&pkg, HRTO_P_HEADER, i + 1, 4);
		while (hashratio_send_pkg(&pkg, thr) != HRTO_SEND_OK)
			;

	}
	return 0;
}

static int hashratio_get_result(struct thr_info *thr, struct hashratio_ret *ar)
{
	struct cgpu_info *hashratio;
	struct hashratio_info *info;
//	int fd;
	
//	fd = fd_detect;
	if (thr) {
		hashratio = thr->cgpu;
		info = hashratio->device_data;
//		fd = info->fd;
	}
	
	uint8_t result[HRTO_READ_SIZE];
	int ret;
	
	memset(result, 0, HRTO_READ_SIZE);
	
//	ret = hashratio_gets(fd, result);
	ret = hashratio_read(hashratio, result, HRTO_READ_SIZE, C_HASHRATIO_READ);
	if (ret != HRTO_GETS_OK)
		return ret;
	
	if (opt_debug) {
		applog(LOG_DEBUG, "Hashratio: Get(ret = %d):", ret);
		hexdump((uint8_t *)result, HRTO_READ_SIZE);
	}
	
	return decode_pkg(thr, ar, result);
}

//static int hashratio_get_result(struct thr_info *thr, int fd_detect, struct hashratio_ret *ar)
//{
//	struct cgpu_info *hashratio;
//	struct hashratio_info *info;
//	int fd;
//
//	fd = fd_detect;
//	if (thr) {
//		hashratio = thr->cgpu;
//		info = hashratio->device_data;
//		fd = info->fd;
//	}
//
//	uint8_t result[HRTO_READ_SIZE];
//	int ret;
//
//	memset(result, 0, HRTO_READ_SIZE);
//
//	ret = hashratio_gets(fd, result);
//	if (ret != HRTO_GETS_OK)
//		return ret;
//
//	if (opt_debug) {
//		applog(LOG_DEBUG, "Hashratio: Get(ret = %d):", ret);
//		hexdump((uint8_t *)result, HRTO_READ_SIZE);
//	}
//
//	return decode_pkg(thr, ar, result);
//}


static struct cgpu_info *hashratio_detect_one(libusb_device *dev, struct usb_find_devices *found)
{
//	int baud, miner_count, asic_count, timeout, frequency, asic;
	int baud, miner_count, asic_count, timeout, asic;
	int this_option_offset;
	struct hashratio_info *info;
	struct cgpu_info *hashratio;
	bool configured;
	int ret;
	
	hashratio = usb_alloc_cgpu(&hashratio_drv, HRTO_MINER_THREADS);
	
//	baud        = HRTO_IO_SPEED;
//	miner_count = HRTO_DEFAULT_MINERS;
//	asic_count  = HRTO_DEFAULT_ASIC_NUM;
//	timeout     = HRTO_DEFAULT_TIMEOUT;
//	frequency = AVALON_DEFAULT_FREQUENCY;
//	asic        = HRTO_AM_BE200;
	
	if (!usb_init(hashratio, dev, found))
		goto shin;
	
//	this_option_offset = usb_ident(hashratio) == IDENT_BBF ? ++bbf_option_offset : ++option_offset;
//	configured = get_options(this_option_offset, &baud, &miner_count,
//							 &asic_count, &timeout, &frequency, &asic,
//							 (usb_ident(avalon) == IDENT_BBF && opt_bitburner_fury_options != NULL) ? opt_bitburner_fury_options : opt_avalon_options);
	
	/* Even though this is an FTDI type chip, we want to do the parsing
	 * all ourselves so set it to std usb type */
	hashratio->usbdev->usb_type = USB_TYPE_STD;
	
	/* We have a real Hashratio! */
	hashratio_initialise(hashratio);
//	quit(1, "hashratio_initialise");
	
	hashratio->device_data = calloc(sizeof(struct hashratio_info), 1);
	if (unlikely(!(hashratio->device_data)))
		quit(1, "Failed to calloc avalon_info data");
	info = hashratio->device_data;
	
//	if (configured) {
//		info->asic = asic;
//		info->baud = baud;
//		info->miner_count = miner_count;
//		info->asic_count = asic_count;
//		info->timeout = timeout;
//		info->frequency = frequency;
//	} else {
//		info->asic = AVALON_A3256;
//		info->baud = HRTO_IO_SPEED;
//		info->asic_count = AVALON_DEFAULT_ASIC_NUM;
//		switch (usb_ident(avalon)) {
//			case IDENT_BBF:
//				info->miner_count = BITBURNER_FURY_DEFAULT_MINER_NUM;
//				info->timeout = BITBURNER_FURY_DEFAULT_TIMEOUT;
//				info->frequency = BITBURNER_FURY_DEFAULT_FREQUENCY;
//				break;
//			default:
//				info->miner_count = AVALON_DEFAULT_MINER_NUM;
//				info->timeout = AVALON_DEFAULT_TIMEOUT;
//				info->frequency = AVALON_DEFAULT_FREQUENCY;
//		}
//	}
//	if (info->asic == AVALON_A3255)
//		info->increment = info->decrement = 50;
//	else {
//		info->increment = 2;
//		info->decrement = 1;
//	}
	
	info->timeout = HRTO_DEFAULT_TIMEOUT;
	info->fan_pwm = HRTO_DEFAULT_FAN_MIN_PWM;
	/* This is for check the temp/fan every 3~4s */
	info->temp_history_count = (4 / (float)((float)info->timeout * ((float)1.67/0x32))) + 1;
//	info->temp_history_count =
//	(4 / (float)((float)info->timeout * (AVALON_A3256 / info->asic) * ((float)1.67/0x32))) + 1;
	if (info->temp_history_count <= 0)
		info->temp_history_count = 1;
	
	info->temp_max = 0;
	info->temp_history_index = 0;
	info->temp_sum = 0;
	info->temp_old = 0;
	
	if (!add_cgpu(hashratio))
		goto unshin;
	
//	ret = avalon_reset(avalon, true);
//	if (ret && !configured)
//		goto unshin;
	
	update_usb_stats(hashratio);
//	avalon_idle(avalon, info);

	applog(LOG_DEBUG, "Hashratio Detected: %s (timeout=%d)",
	       hashratio->device_path, info->timeout);
	
//	applog(LOG_DEBUG, "Hashratio Detected: %s "
//	       "(miner_count=%d asic_count=%d timeout=%d frequency=%d chip=%d)",
//	       avalon->device_path, info->miner_count, info->asic_count, info->timeout,
//	       info->frequency, info->asic);
//	
//	if (usb_ident(avalon) == IDENT_BTB) {
//		if (opt_bitburner_core_voltage < BITBURNER_MIN_COREMV ||
//		    opt_bitburner_core_voltage > BITBURNER_MAX_COREMV) {
//			quit(1, "Invalid bitburner-voltage %d must be %dmv - %dmv",
//				 opt_bitburner_core_voltage,
//				 BITBURNER_MIN_COREMV,
//				 BITBURNER_MAX_COREMV);
//		} else
//			bitburner_set_core_voltage(avalon, opt_bitburner_core_voltage);
//	} else if (usb_ident(avalon) == IDENT_BBF) {
//		if (opt_bitburner_fury_core_voltage < BITBURNER_FURY_MIN_COREMV ||
//		    opt_bitburner_fury_core_voltage > BITBURNER_FURY_MAX_COREMV) {
//			quit(1, "Invalid bitburner-fury-voltage %d must be %dmv - %dmv",
//				 opt_bitburner_fury_core_voltage,
//				 BITBURNER_FURY_MIN_COREMV,
//				 BITBURNER_FURY_MAX_COREMV);
//		} else
//			bitburner_set_core_voltage(avalon, opt_bitburner_fury_core_voltage);
//	}
	
//	if (is_bitburner(avalon)) {
//		bitburner_get_version(avalon);
//	}
	
	return hashratio;
	
unshin:
	
	usb_uninit(hashratio);
	
shin:
	
	free(hashratio->device_data);
	hashratio->device_data = NULL;
	
	hashratio = usb_free_cgpu(hashratio);
	
	return NULL;
}



static void hashratio_initialise(struct cgpu_info *hashratio)
{
	int err, interface;
	
	if (hashratio->usbinfo.nodev)
		return;
	
	interface = usb_interface(hashratio);
	// Reset
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_RESET,
					   FTDI_VALUE_RESET, interface, C_RESET);
	
	applog(LOG_DEBUG, "%s%i: reset got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set latency
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_LATENCY,
					   HRTO_LATENCY, interface, C_LATENCY);
	
	applog(LOG_DEBUG, "%s%i: latency got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set data
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_DATA,
					   FTDI_VALUE_DATA_HRTO, interface, C_SETDATA);
	
	applog(LOG_DEBUG, "%s%i: data got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set the baud
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_BAUD,
					   FTDI_VALUE_BAUD_HRTO,
					   (FTDI_INDEX_BAUD_HRTO & 0xff00) | interface, C_SETBAUD);
	
	applog(LOG_DEBUG, "%s%i: setbaud got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set Modem Control
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
					   FTDI_VALUE_MODEM, interface, C_SETMODEM);
	
	applog(LOG_DEBUG, "%s%i: setmodemctrl got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set Flow Control
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
					   FTDI_VALUE_FLOW, interface, C_SETFLOW);
	
	applog(LOG_DEBUG, "%s%i: setflowctrl got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	/* Avalon repeats the following */
	// Set Modem Control
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
					   FTDI_VALUE_MODEM, interface, C_SETMODEM);
	
	applog(LOG_DEBUG, "%s%i: setmodemctrl 2 got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
	if (hashratio->usbinfo.nodev)
		return;
	
	// Set Flow Control
	err = usb_transfer(hashratio, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
					   FTDI_VALUE_FLOW, interface, C_SETFLOW);
	
	applog(LOG_DEBUG, "%s%i: setflowctrl 2 got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
}


//static inline void hashratio_detect(bool __maybe_unused hotplug)
//{
//	serial_detect(&hashratio_drv, hashratio_detect_one);
//}

static void hashratio_detect(bool __maybe_unused hotplug)
{
	usb_detect(&hashratio_drv, hashratio_detect_one);
}


//static void hashratio_init(struct cgpu_info *hashratio)
//{
//	int fd;
//	struct hashratio_info *info = hashratio->device_data;
//
//	fd = hashratio_open(hashratio->device_path, info->baud, true);
//	if (unlikely(fd == -1)) {
//		applog(LOG_ERR, "Hashratio: Failed to open on %s", hashratio->device_path);
//		return;
//	}
//	applog(LOG_DEBUG, "Hashratio: Opened on %s", hashratio->device_path);
//
//	info->fd = fd;
//}

static void hashratio_init(struct cgpu_info *hashratio)
{
	applog(LOG_INFO, "Avalon: Opened on %s", hashratio->device_path);
}

static bool hashratio_prepare(struct thr_info *thr)
{
	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;

	if (hashratio->works != NULL) {
		free(hashratio->works);
	}
	hashratio->works = calloc(sizeof(struct work *), 2);
	if (!hashratio->works)
		quit(1, "Failed to calloc hashratio works in hashratio_prepare");

//	if (info->fd == -1)
//		hashratio_init(hashratio);

//	info->thr   = thr;
	info->first = true;

	hashratio_init(hashratio);
	
	return true;
}

static int polling(struct thr_info *thr)
{
	int i, tmp;

	struct hashratio_pkg send_pkg;
	struct hashratio_ret ar;

	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;

//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		if (info->modulars[i]) {
			memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
			tmp = be32toh(i);
			memcpy(send_pkg.data + 28, &tmp, 4);
			hashratio_init_pkg(&send_pkg, HRTO_P_POLLING, 1, 1);

			while (hashratio_send_pkg(&send_pkg, thr) != HRTO_SEND_OK)
				;
//			hashratio_get_result(thr, info->fd, &ar);
			hashratio_get_result(thr, &ar);
//		}
//	}

	return 0;
}

static int64_t hashratio_scanhash(struct thr_info *thr)
{
	struct hashratio_pkg send_pkg;

	struct pool *pool;
	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;

	int64_t h;
	uint32_t tmp, range, start;
	int i;

	if (thr->work_restart || thr->work_update || info->first) {
		info->new_stratum = true;
		applog(LOG_DEBUG, "Hashratio: New stratum: restart: %d, update: %d, first: %d",
		       thr->work_restart, thr->work_update, info->first);
		thr->work_update = false;
		thr->work_restart = false;
		if (unlikely(info->first))
			info->first = false;

		get_work(thr, thr->id); /* Make sure pool is ready */

		pool = current_pool();
		if (!pool->has_stratum)
			quit(1, "Hashratio: Miner Manager have to use stratum pool");
		if (pool->coinbase_len > HRTO_P_COINBASE_SIZE)
			quit(1, "Hashratio: Miner Manager pool coinbase length have to less then %d", HRTO_P_COINBASE_SIZE);
		if (pool->merkles > HRTO_P_MERKLES_COUNT)
			quit(1, "Hashratio: Miner Manager merkles have to less then %d", HRTO_P_MERKLES_COUNT);

		info->diff = (int)pool->swork.diff - 1;
		info->pool_no = pool->pool_no;

		cg_wlock(&pool->data_lock);
		hashratio_stratum_pkgs(pool, thr);
		cg_wunlock(&pool->data_lock);

		/* Configuer the parameter from outside */
		info->fan_pwm = opt_hashratio_fan_min;

		/* Set the Fan */
		memset(send_pkg.data, 0, HRTO_P_DATA_LEN);

		tmp = be32toh(info->fan_pwm);
		memcpy(send_pkg.data, &tmp, 4);

		/* Configure the nonce2 offset and range */
		range = 0xffffffff / total_devices;
		start = range * hashratio->device_id;

		tmp = be32toh(start);
		memcpy(send_pkg.data + 12, &tmp, 4);

		tmp = be32toh(range);
		memcpy(send_pkg.data + 16, &tmp, 4);

		/* Package the data */
		hashratio_init_pkg(&send_pkg, HRTO_P_SET, 1, 1);
		while (hashratio_send_pkg(&send_pkg, thr) != HRTO_SEND_OK)
			;
		info->new_stratum = false;
	}

	polling(thr);

	h = 0;
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		h += info->local_work[i];
//	}
	h += info->local_work;
	return h * 0xffffffff;
}

static struct api_data *hashratio_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct hashratio_info *info = cgpu->device_data;
	int i, a, b;
	char buf[24];
	double hwp;
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "ID%d MM Version", i + 1);
//		root = api_add_string(root, buf, &(info->mm_version[i]), false);
//		root = api_add_string(root, buf, info->mm_version[i], false);
//	}
	sprintf(buf, "ID%d MM Version", 1);
	root = api_add_string(root, buf, info->mm_version, false);
	
//	for (i = 0; i < HRTO_DEFAULT_MINERS * HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "Match work count%02d", i + 1);
//		root = api_add_int(root, buf, &(info->matching_work[i]), false);
//	}
	for (i = 0; i < HRTO_DEFAULT_MINERS; i++) {
		sprintf(buf, "Match work count%02d", i + 1);
		root = api_add_int(root, buf, &(info->matching_work[i]), false);
	}
	
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "Local works%d", i + 1);
//		root = api_add_int(root, buf, &(info->local_works[i]), false);
//	}
	sprintf(buf, "Local works%d", 1);
	root = api_add_int(root, buf, &(info->local_works), false);
	
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "Hardware error works%d", i + 1);
//		root = api_add_int(root, buf, &(info->hw_works[i]), false);
//	}
	sprintf(buf, "Hardware error works%d", 1);
	root = api_add_int(root, buf, &(info->hw_works), false);
	
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		a = info->hw_works[i];
//		b = info->local_works[i];
//		hwp = b ? ((double)a / (double)b) : 0;
//
//		sprintf(buf, "Device hardware error%d%%", i + 1);
//		root = api_add_percent(root, buf, &hwp, true);
//	}
	a = info->hw_works;
	b = info->local_works;
	hwp = b ? ((double)a / (double)b) : 0;
	sprintf(buf, "Device hardware error%d%%", 1);
	root = api_add_percent(root, buf, &hwp, true);
	
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "Temperature%d", i + 1);
//		root = api_add_int(root, buf, &(info->temp[i]), false);
//	}
	sprintf(buf, "Temperature%d", 1);
	root = api_add_int(root, buf, &(info->temp), false);
	
//	for (i = 0; i < HRTO_DEFAULT_MODULARS; i++) {
//		sprintf(buf, "Fan%d", i + 1);
//		root = api_add_int(root, buf, &(info->fan[i]), false);
//	}
	sprintf(buf, "Fan%d", 1);
	root = api_add_int(root, buf, &(info->fan), false);

	return root;
}

static void hashratio_shutdown(struct thr_info *thr)
{
	struct cgpu_info *hashratio = thr->cgpu;

	free(hashratio->works);
	hashratio->works = NULL;
}

static int hashratio_read(struct cgpu_info *hashratio, char *buf, size_t bufsize, int ep)
{
	size_t total = 0, readsize = bufsize + 2;
	char readbuf[HRTO_READBUF_SIZE];
	int err, amount, ofs = 2, cp;
	
	err = usb_read_once(hashratio, readbuf, readsize, &amount, ep);
	applog(LOG_DEBUG, "%s%i: Get avalon read got err %d",
	       hashratio->drv->name, hashratio->device_id, err);
	if (err && err != LIBUSB_ERROR_TIMEOUT)
		return err;
	
	if (amount < 2)
		goto out;
	
	/* The first 2 of every 64 bytes are status on FTDIRL */
	while (amount > 2) {
		cp = amount - 2;
		if (cp > 62)
			cp = 62;
		memcpy(&buf[total], &readbuf[ofs], cp);
		total += cp;
		amount -= cp + 2;
		ofs += 64;
	}
out:
	return total;
}

static int hashratio_write(struct cgpu_info *hashratio, char *buf, ssize_t len, int ep)
{
	int err, amount;
	
	if (opt_debug) {
		applog(LOG_DEBUG, "hashratio_write(%u):", (unsigned int)len);
		hexdump(buf, len);
	}

//	struct hashratio_info *info = hashratio->device_data;
//	delay = len * 10 * 1000000;
//	delay = delay / info->baud;
//	delay += 4000;
	
//	/* Sleep from the last time we sent data */
//	cgsleep_us_r(&info->cgsent, info->send_delay);
//	cgsleep_prepare_r(&info->cgsent);
	
	err = usb_write(hashratio, buf, len, &amount, ep);
	applog(LOG_DEBUG, "%s%i: usb_write got err %d",
		   hashratio->drv->name, hashratio->device_id, err);
	
//	applog(LOG_DEBUG, "Hashratio: Sent: Buffer delay: %dus", info->send_delay);
//	info->send_delay = delay;
	
	if (unlikely(err != 0)) {
		applog(LOG_WARNING, "usb_write error on hashratio_write");
		return HRTO_SEND_ERROR;
	}
	if (amount != len) {
		applog(LOG_WARNING, "usb_write length mismatch on hashratio_write");
		return HRTO_SEND_ERROR;
	}
	
	return HRTO_SEND_OK;
}

struct device_drv hashratio_drv = {
	.drv_id = DRIVER_hashratio,
	.dname = "hashratio",
	.name = "HRTO",
	.get_api_stats = hashratio_api_stats,
	.drv_detect = hashratio_detect,
	.reinit_device = hashratio_init,
	.thread_prepare = hashratio_prepare,
	.hash_work = hash_driver_work,
	.scanwork = hashratio_scanhash,
	.thread_shutdown = hashratio_shutdown,
};
