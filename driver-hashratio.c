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

int opt_hashratio_fan_min = HRTO_DEFAULT_FAN_MIN;
int opt_hashratio_fan_max = HRTO_DEFAULT_FAN_MAX;

int opt_hashratio_freq = HRTO_DEFAULT_FREQUENCY;


static int get_fan_pwm(int temp) {
	int pwm;
	uint8_t fan_pwm_arr[] = {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
		30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
		30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
		30, 37, 49, 61, 73, 85, 88, 91, 94, 97, 100, 100, 100, 100, 100, 100,
		100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
		100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
		100, 100, 100, 100, 100, 100, 100};
	if (temp < 0 || temp >= sizeof(fan_pwm_arr)/sizeof(fan_pwm_arr[0]) ||
		fan_pwm_arr[temp] > opt_hashratio_fan_max) {
		return opt_hashratio_fan_max;
	}
	pwm = HRTO_PWM_MAX - fan_pwm_arr[temp] * HRTO_PWM_MAX / 100;

	if (pwm < opt_hashratio_fan_min) {
		return opt_hashratio_fan_min;
	}
	if (pwm > opt_hashratio_fan_max) {
		return opt_hashratio_fan_max;
	}
	return pwm;
}

char *set_hashratio_freq(char *arg)
{
	int val, ret;
	
	ret = sscanf(arg, "%d", &val);
	if (ret != 1)
		return "No values passed to hashratio-freq";
	
	if (val < HRTO_DEFAULT_FREQUENCY_MIN || val > HRTO_DEFAULT_FREQUENCY_MAX)
		return "Invalid value passed to hashratio-freq";
	
	opt_hashratio_freq = val;
	
	return NULL;
}

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


extern void submit_nonce2_nonce(struct thr_info *thr, uint32_t pool_no, uint32_t nonce2, uint32_t nonce);
static int decode_pkg(struct thr_info *thr, struct hashratio_ret *ar, uint8_t *pkg)
{
	struct cgpu_info *hashratio;
	struct hashratio_info *info;
	struct pool *pool;

	unsigned int expected_crc;
	unsigned int actual_crc;
	uint32_t nonce, nonce2, miner;
	int pool_no;
	uint8_t job_id[5];
	int tmp;

	int type = HRTO_GETS_ERROR;
	if (thr) {
		hashratio = thr->cgpu;
		info = hashratio->device_data;
	}
//	else // FIXME: Should this happen at all!?
//		return 0;

	memcpy((uint8_t *)ar, pkg, HRTO_READ_SIZE);

	applog(LOG_DEBUG, "pkg.type, hex: %02x, dec: %d", ar->type, ar->type);
	
	if (ar->head[0] == HRTO_H1 && ar->head[1] == HRTO_H2) {
		expected_crc = crc16(ar->data, HRTO_P_DATA_LEN);
		actual_crc = (ar->crc[0] & 0xff) |
			((ar->crc[1] & 0xff) << 8);

		type = ar->type;
		applog(LOG_DEBUG, "hashratio: %d: expected crc(%04x), actural_crc(%04x)", type, expected_crc, actual_crc);
		if (expected_crc != actual_crc)
			goto out;
		
		switch(type) {
		case HRTO_P_NONCE:
			memcpy(&miner,   ar->data + 0, 4);
			memcpy(&pool_no, ar->data + 4, 4);
			memcpy(&nonce2,  ar->data + 8, 4);
			/* Calc time    ar->data + 12 */
			memcpy(&nonce, ar->data + 12, 4);
			memset(job_id, 0, 5);
			memcpy(job_id, ar->data + 16, 4);

			miner = be32toh(miner);
			pool_no = be32toh(pool_no);
			if (miner >= HRTO_DEFAULT_MINERS || pool_no >= total_pools || pool_no < 0) {
				applog(LOG_DEBUG, "hashratio: Wrong miner/pool/id no %d,%d", miner, pool_no);
				break;
			} else
				info->matching_work[miner]++;
			nonce2 = be32toh(nonce2);
			nonce = be32toh(nonce);
//			nonce -= 0x180;

			applog(LOG_DEBUG, "hashratio: Found! [%s] %d:(%08x) (%08x)",
			       job_id, pool_no, nonce2, nonce);
			/* FIXME:
			 * We need remember the pre_pool. then submit the stale work */
//			pool = pools[pool_no];
//			if (job_idcmp(job_id, pool->swork.job_id))
//				break;

			if (thr && !info->new_stratum)
				submit_nonce2_nonce(thr, pool_no, nonce2, nonce);
			break;
		case HRTO_P_STATUS:
			memcpy(&tmp, ar->data, 4);
			tmp = be32toh(tmp);
			info->temp_max = info->temp = tmp;
//			info->temp[1] = tmp & 0xffff;

			memcpy(&tmp, ar->data + 4, 4);
			tmp = be32toh(tmp);
			info->fan[0] = tmp >> 16;
			info->fan[1] = tmp & 0xffff;

			// local_work
			memcpy(&tmp, ar->data + 8, 4);
			tmp = be32toh(tmp);
			info->local_works += tmp;
			
			// hw_work
			memcpy(&tmp, ar->data + 12, 4);
			tmp = be32toh(tmp);
			info->hw_works += tmp;
			
			hashratio->temp = info->temp;
			break;
//		case HRTO_P_GET_FREQ:
//				if (ar->cnt != HRTO_DEFAULT_MODULARS) {
//					applog(LOG_DEBUG, "pkg count is NOT match modulars");
//					break;
//				}
//				memcpy(info->freq + ar->idx * HRTO_P_DATA_LEN,
//					   ar->data, ar->idx < 2 ? HRTO_P_DATA_LEN : 16);
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
	}

out:
	return type;
}

static inline int hashratio_gets(int fd, uint8_t *buf)
{
	int i;
	int read_amount = HRTO_READ_SIZE;
	uint8_t buf_tmp[HRTO_READ_SIZE];
	uint8_t buf_copy[2 * HRTO_READ_SIZE];
	uint8_t *buf_back = buf;
	ssize_t ret = 0;

	while (true) {
		struct timeval timeout;
		fd_set rd;

		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		FD_ZERO(&rd);
		FD_SET(fd, &rd);
		ret = select(fd + 1, &rd, NULL, NULL, &timeout);
		if (unlikely(ret < 0)) {
			applog(LOG_ERR, "hashratio: Error %d on select in hashratio_gets", errno);
			return HRTO_GETS_ERROR;
		}
		if (ret) {
			memset(buf, 0, read_amount);
			ret = read(fd, buf, read_amount);
			if (unlikely(ret < 0)) {
				applog(LOG_ERR, "hashratio: Error %d on read in hashratio_gets", errno);
				return HRTO_GETS_ERROR;
			}
			if (likely(ret >= read_amount)) {
				for (i = 1; i < read_amount; i++) {
					if (buf_back[i - 1] == HRTO_H1 && buf_back[i] == HRTO_H2)
						break;
				}
				i -= 1;
				if (i) {
					ret = read(fd, buf_tmp, i);
					if (unlikely(ret != i)) {
						applog(LOG_ERR, "hashratio: Error %d on read in hashratio_gets", errno);
						return HRTO_GETS_ERROR;
					}
					memcpy(buf_copy, buf_back + i, HRTO_READ_SIZE - i);
					memcpy(buf_copy + HRTO_READ_SIZE - i, buf_tmp, i);
					memcpy(buf_back, buf_copy, HRTO_READ_SIZE);
				}
				return HRTO_GETS_OK;
			}
			buf += ret;
			read_amount -= ret;
			continue;
		}

		return HRTO_GETS_TIMEOUT;
	}
}

static int hashratio_send_pkg(int fd, const struct hashratio_pkg *pkg,
			    struct thr_info __maybe_unused *thr)
{
	int ret;
	uint8_t buf[HRTO_WRITE_SIZE];
	int nr_len = HRTO_WRITE_SIZE;

	memcpy(buf, pkg, HRTO_WRITE_SIZE);
	if (opt_debug) {
		applog(LOG_DEBUG, "hashratio: Sent(%d):", nr_len);
		hexdump((uint8_t *)buf, nr_len);
	}

	ret = write(fd, buf, nr_len);
	if (unlikely(ret != nr_len)) {
		applog(LOG_DEBUG, "hashratio: Send(%d)!", ret);
		return HRTO_SEND_ERROR;
	}

	cgsleep_ms(20);
#if 0
	ret = hashratio_gets(fd, result);
	if (ret != HRTO_GETS_OK) {
		applog(LOG_DEBUG, "hashratio: Get(%d)!", ret);
		return HRTO_SEND_ERROR;
	}

	ret = decode_pkg(thr, &ar, result);
	if (ret != HRTO_P_ACK) {
		applog(LOG_DEBUG, "hashratio: PKG(%d)!", ret);
		hexdump((uint8_t *)result, HRTO_READ_SIZE);
		return HRTO_SEND_ERROR;
	}
#endif

	return HRTO_SEND_OK;
}

static int hashratio_stratum_pkgs(int fd, struct pool *pool, struct thr_info *thr)
{
	const int merkle_offset = 36;
	struct hashratio_pkg pkg;
	int i, a, b, tmp;
	unsigned char target[32];
	int job_id_len;

	/* Send out the first stratum message STATIC */
	applog(LOG_DEBUG, "hashratio: Pool stratum message STATIC: %d, %d, %d, %d, %d",
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

	tmp = be32toh((int)pool->swork.diff);
	memcpy(pkg.data + 20, &tmp, 4);

	tmp = be32toh((int)pool->pool_no);
	memcpy(pkg.data + 24, &tmp, 4);

	hashratio_init_pkg(&pkg, HRTO_P_STATIC, 1, 1);
	while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
		;

	set_target(target, pool->swork.diff);
	memcpy(pkg.data, target, 32);
	if (opt_debug) {
		char *target_str;
		target_str = bin2hex(target, 32);
		applog(LOG_DEBUG, "hashratio: Pool stratum target: %s", target_str);
		free(target_str);
	}
	hashratio_init_pkg(&pkg, HRTO_P_TARGET, 1, 1);
	while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
		;


	applog(LOG_DEBUG, "hashratio: Pool stratum message JOBS_ID: %s",
	       pool->swork.job_id);
	memset(pkg.data, 0, HRTO_P_DATA_LEN);

	job_id_len = strlen(pool->swork.job_id);
	job_id_len = job_id_len >= 4 ? 4 : job_id_len;
	for (i = 0; i < job_id_len; i++) {
		pkg.data[i] = *(pool->swork.job_id + strlen(pool->swork.job_id) - 4 + i);
	}
	hashratio_init_pkg(&pkg, HRTO_P_JOB_ID, 1, 1);
	while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
		;

	a = pool->coinbase_len / HRTO_P_DATA_LEN;
	b = pool->coinbase_len % HRTO_P_DATA_LEN;
	applog(LOG_DEBUG, "pool->coinbase_len: %d", pool->coinbase_len);
	applog(LOG_DEBUG, "hashratio: Pool stratum message COINBASE: %d %d", a, b);
	for (i = 0; i < a; i++) {
		memcpy(pkg.data, pool->coinbase + i * 32, 32);
		hashratio_init_pkg(&pkg, HRTO_P_COINBASE, i + 1, a + (b ? 1 : 0));
		while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
			;
		if (i % 25 == 0) {
			cgsleep_ms(2);
		}
	}
	if (b) {
		memset(pkg.data, 0, HRTO_P_DATA_LEN);
		memcpy(pkg.data, pool->coinbase + i * 32, b);
		hashratio_init_pkg(&pkg, HRTO_P_COINBASE, i + 1, i + 1);
		while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
			;
	}

	b = pool->merkles;
	applog(LOG_DEBUG, "hashratio: Pool stratum message MERKLES: %d", b);
	for (i = 0; i < b; i++) {
		memset(pkg.data, 0, HRTO_P_DATA_LEN);
		memcpy(pkg.data, pool->swork.merkle_bin[i], 32);
		hashratio_init_pkg(&pkg, HRTO_P_MERKLES, i + 1, b);
		while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
			;
	}

	applog(LOG_DEBUG, "hashratio: Pool stratum message HEADER: 4");
	for (i = 0; i < 4; i++) {
		memset(pkg.data, 0, HRTO_P_HEADER);
		memcpy(pkg.data, pool->header_bin + i * 32, 32);
		hashratio_init_pkg(&pkg, HRTO_P_HEADER, i + 1, 4);
		while (hashratio_send_pkg(fd, &pkg, thr) != HRTO_SEND_OK)
			;

	}
	return 0;
}

static int hashratio_get_result(struct thr_info *thr, int fd_detect, struct hashratio_ret *ar)
{
	struct cgpu_info *hashratio;
	struct hashratio_info *info;
	int fd;

	fd = fd_detect;
	if (thr) {
		hashratio = thr->cgpu;
		info = hashratio->device_data;
		fd = info->fd;
	}

	uint8_t result[HRTO_READ_SIZE];
	int ret;

	memset(result, 0, HRTO_READ_SIZE);

	ret = hashratio_gets(fd, result);
	if (ret != HRTO_GETS_OK)
		return ret;

	if (opt_debug) {
		applog(LOG_DEBUG, "hashratio: Get(ret = %d):", ret);
		hexdump((uint8_t *)result, HRTO_READ_SIZE);
	}

	return decode_pkg(thr, ar, result);
}

static bool hashratio_detect_one(const char *devpath)
{
	struct hashratio_info *info;
	int ackdetect;
	int fd;
	int tmp, i;
	char mm_version[16];

	struct cgpu_info *hashratio;
	struct hashratio_pkg detect_pkg;
	struct hashratio_ret ret_pkg;

	applog(LOG_DEBUG, "hashratio Detect: Attempting to open %s", devpath);
	
	fd = hashratio_open(devpath, HRTO_IO_SPEED, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "hashratio Detect: Failed to open %s", devpath);
		return false;
	}
	tcflush(fd, TCIOFLUSH);

	strcpy(mm_version, "NONE");
	/* Send out detect pkg */
	memset(detect_pkg.data, 0, HRTO_P_DATA_LEN);

	hashratio_init_pkg(&detect_pkg, HRTO_P_DETECT, 1, 1);
	hashratio_send_pkg(fd, &detect_pkg, NULL);
	ackdetect = hashratio_get_result(NULL, fd, &ret_pkg);
	applog(LOG_DEBUG, "hashratio Detect ID: %d", ackdetect);
	
	if (ackdetect != HRTO_P_ACKDETECT)
		return false;

	memcpy(mm_version, ret_pkg.data, 15);
	mm_version[15] = '\0';

	/* We have a real Hashratio! */
	hashratio = calloc(1, sizeof(struct cgpu_info));
	hashratio->drv = &hashratio_drv;
	hashratio->device_path = strdup(devpath);
	hashratio->threads = HRTO_MINER_THREADS;
	add_cgpu(hashratio);

	applog(LOG_INFO, "hashratio Detect: Found at %s, mark as %d",
	       devpath, hashratio->device_id);

	hashratio->device_data = calloc(sizeof(struct hashratio_info), 1);
	if (unlikely(!(hashratio->device_data)))
		quit(1, "Failed to malloc hashratio_info");

	info = hashratio->device_data;

	strcpy(info->mm_version, mm_version);

	info->baud     = HRTO_IO_SPEED;
	info->fan_pwm  = HRTO_DEFAULT_FAN_PWM;
	info->temp_max = 0;
	info->temp_history_index = 0;
	info->temp_sum = 0;
	info->temp_old = 0;
	info->default_freq = opt_hashratio_freq;
//	info->get_result_counter = 0;

	info->fd = -1;
	/* Set asic to idle mode after detect */
	hashratio_close(fd);

	return true;
}

static inline void hashratio_detect(bool __maybe_unused hotplug)
{
	serial_detect(&hashratio_drv, hashratio_detect_one);
}

static void hashratio_init(struct cgpu_info *hashratio)
{
	int fd;
	struct hashratio_info *info = hashratio->device_data;

	fd = hashratio_open(hashratio->device_path, info->baud, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "hashratio: Failed to open on %s", hashratio->device_path);
		return;
	}
	applog(LOG_DEBUG, "hashratio: Opened on %s", hashratio->device_path);

	info->fd = fd;
}

static bool hashratio_prepare(struct thr_info *thr)
{
	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;

	free(hashratio->works);
	hashratio->works = calloc(sizeof(struct work *), 2);
	if (!hashratio->works)
		quit(1, "Failed to calloc hashratio works in hashratio_prepare");

	if (info->fd == -1)
		hashratio_init(hashratio);

	info->first = true;

	return true;
}

static int polling(struct thr_info *thr)
{
	int i, tmp;

	struct hashratio_pkg send_pkg;
	struct hashratio_ret ar;

	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;

	memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
	hashratio_init_pkg(&send_pkg, HRTO_P_POLLING, 1, 1);

	while (hashratio_send_pkg(info->fd, &send_pkg, thr) != HRTO_SEND_OK)
		;
	hashratio_get_result(thr, info->fd, &ar);
	
//	info->get_result_counter++;
//	
//	// get status
//	if (info->get_result_counter % 10 == 0) {
//		memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
//		hashratio_init_pkg(&send_pkg, HRTO_P_STATUS, 1, 1);
//		
//		while (hashratio_send_pkg(info->fd, &send_pkg, thr) != HRTO_SEND_OK)
//			;
//		hashratio_get_result(thr, info->fd, &ar);
//	}

	return 0;
}


static void hashratio_freq_set(struct thr_info *thr) {
	struct hashratio_pkg send_pkg;
	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;
	
	int i, j, n;
	double matching_work_avg, ratio, new_freq;
	
	// calc avg matching work
	for (i = 0; i < HRTO_DEFAULT_MINERS; i++) {
		matching_work_avg += info->matching_work[i];
	}
	matching_work_avg /= HRTO_DEFAULT_MINERS;
	
	// calc target freq
	if (info->default_freq >= HRTO_DEFAULT_FREQUENCY_MIN && matching_work_avg >= 800) {
		for (i = 0; i < HRTO_DEFAULT_MINERS; i++) {
			ratio = (double)info->matching_work[i] / matching_work_avg;
			if (ratio > 1.0) {
//				new_freq = ratio * (HRTO_DEFAULT_FREQUENCY_MAX - info->default_freq) + info->default_freq;
				new_freq = ratio * info->default_freq;
				if (new_freq > HRTO_DEFAULT_FREQUENCY_MAX) {
					new_freq = HRTO_DEFAULT_FREQUENCY_MAX;
				}
			} else {
				new_freq = ratio * (info->default_freq - HRTO_DEFAULT_FREQUENCY_MIN) + HRTO_DEFAULT_FREQUENCY_MIN;
			}
			info->target_freq[i] = (int)new_freq;
		}
	}
	
	// send freq settings
	n = HRTO_DEFAULT_MINERS / HRTO_P_DATA_LEN;
	for (i = 0; i <= n; i++) {
		memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
		if (i == n) {
			j = HRTO_DEFAULT_MINERS % HRTO_P_DATA_LEN - 1;
		} else {
			j = HRTO_P_DATA_LEN - 1;
		}
		// copy freq to data
		for (; j >= 0; j--) {
			send_pkg.data[j] = info->target_freq[i * HRTO_P_DATA_LEN + j];
		}
		hashratio_init_pkg(&send_pkg, HRTO_P_SET_FREQ, i, n);
		while (hashratio_send_pkg(info->fd, &send_pkg, thr) != HRTO_SEND_OK)
			;
	}
}

static int64_t hashratio_scanhash(struct thr_info *thr)
{
	struct hashratio_pkg send_pkg;

	struct pool *pool;
	struct cgpu_info *hashratio = thr->cgpu;
	struct hashratio_info *info = hashratio->device_data;
	struct hashratio_ret ret_pkg;
	
	int64_t h;
	uint32_t tmp, range, start;
	int i;

	if (thr->work_restart || thr->work_update || info->first) {
		info->new_stratum = true;
		applog(LOG_DEBUG, "hashratio: New stratum: restart: %d, update: %d, first: %d",
		       thr->work_restart, thr->work_update, info->first);
		thr->work_update = false;
		thr->work_restart = false;
		if (unlikely(info->first))
			info->first = false;

		get_work(thr, thr->id); /* Make sure pool is ready */

		pool = current_pool();
		if (!pool->has_stratum)
			quit(1, "hashratio: Miner Manager have to use stratum pool");
		if (pool->coinbase_len > HRTO_P_COINBASE_SIZE)
			quit(1, "hashratio: Miner Manager pool coinbase length have to less then %d", HRTO_P_COINBASE_SIZE);
		if (pool->merkles > HRTO_P_MERKLES_COUNT)
			quit(1, "hashratio: Miner Manager merkles have to less then %d", HRTO_P_MERKLES_COUNT);

		info->diff = (int)pool->swork.diff - 1;
		info->pool_no = pool->pool_no;

		cg_wlock(&pool->data_lock);
		hashratio_stratum_pkgs(info->fd, pool, thr);
		cg_wunlock(&pool->data_lock);
		
		/* Configuer the parameter from outside */
		memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
		
		// fan
//		info->fan_pwm = get_fan_pwm(hashratio->temp);  // set fan pwm
		info->fan_pwm = 800;
		tmp = be32toh(info->fan_pwm);
		memcpy(send_pkg.data, &tmp, 4);

		// freq
//		tmp = be32toh(info->set_frequency);
//		memcpy(send_pkg.data + 4, &tmp, 4);
		
		/* Configure the nonce2 offset and range */
		range = 0xffffffff / total_devices;
		start = range * hashratio->device_id;

		tmp = be32toh(start);
		memcpy(send_pkg.data + 8, &tmp, 4);

		tmp = be32toh(range);
		memcpy(send_pkg.data + 12, &tmp, 4);

		/* Package the data */
		hashratio_init_pkg(&send_pkg, HRTO_P_SET, 1, 1);
		while (hashratio_send_pkg(info->fd, &send_pkg, thr) != HRTO_SEND_OK)
			;
		
		/* pkg: set freq */
//		hashratio_freq_set(thr);
		
		/* pkg: get freq */
//		if (opt_debug) {
//			memset(send_pkg.data, 0, HRTO_P_DATA_LEN);
//			hashratio_init_pkg(&send_pkg, HRTO_P_GET_FREQ, 1, 1);
//			while (hashratio_send_pkg(info->fd, &send_pkg, thr) != HRTO_SEND_OK)
//				;
//			
//			hashratio_get_result(thr, info->fd, &ret_pkg);
//			while (ret_pkg.idx < ret_pkg.cnt) {
//				hashratio_get_result(thr, info->fd, &ret_pkg);
//			}
//			hexdump((uint8_t *)info->freq, HRTO_DEFAULT_MINERS);
//		}
		
		info->new_stratum = false;
	}

	polling(thr);
	cgsleep_ms(50);

	h = 0;
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

	// mm version
	sprintf(buf, "MM Version");
	root = api_add_string(root, buf, info->mm_version, false);
	
	// match work count
	for (i = 0; i < HRTO_DEFAULT_MINERS; i++) {
		sprintf(buf, "Match work count%02d", i + 1);
		root = api_add_int(root, buf, &(info->matching_work[i]), false);
	}
	
	// local works
	sprintf(buf, "Local works");
	root = api_add_int(root, buf, &(info->local_works), false);
	
	// hardware error works
	sprintf(buf, "Hardware error works");
	root = api_add_int(root, buf, &(info->hw_works), false);
	
	// device hardware error %
	hwp = info->local_works ? ((double)info->hw_works / (double)info->local_works) : 0;
	sprintf(buf, "Device hardware error%%");
	root = api_add_percent(root, buf, &hwp, true);
	
	// Temperature
	sprintf(buf, "Temperature");
	root = api_add_int(root, buf, &(info->temp), false);

	// Fan
	for (i = 0; i < HRTO_FAN_COUNT; i++) {
		sprintf(buf, "Fan%d", i+1);
		root = api_add_int(root, buf, &(info->fan[i]), false);
	}

	return root;
}

static void hashratio_shutdown(struct thr_info *thr)
{
	struct cgpu_info *hashratio = thr->cgpu;

	free(hashratio->works);
	hashratio->works = NULL;
}

struct device_drv hashratio_drv = {
	.drv_id = DRIVER_hashratio,
	.dname = "hashratio",
	.name = "HRTO",
	.get_api_stats   = hashratio_api_stats,
	.drv_detect      = hashratio_detect,
	.reinit_device   = hashratio_init,
	.thread_prepare  = hashratio_prepare,
	.hash_work       = hash_driver_work,
	.scanwork        = hashratio_scanhash,
	.thread_shutdown = hashratio_shutdown,
};
