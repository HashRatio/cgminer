/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2014 Xiangfu <xiangfu@openmobilefree.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef _HASHRATIO_H_
#define _HASHRATIO_H_

#include "util.h"
#include "fpgautils.h"

#ifdef USE_HASHRATIO

#define HRTO_MINER_THREADS	1

//#define HRTO_AM_BE200  100

#define HRTO_RESET_FAULT_DECISECONDS 10
#define HRTO_IO_SPEED                115200

#define HRTO_DEFAULT_MINERS     80
//#define HRTO_DEFAULT_MODULARS   1

#define HRTO_PWM_MAX            0x3FF
#define HRTO_DEFAULT_FAN_PWM    80 /* % */
#define HRTO_DEFAULT_FAN_MIN    0
#define HRTO_DEFAULT_FAN_MAX    100
#define HRTO_DEFAULT_FAN_MAX_PWM 0xA0 /* 100% */
#define HRTO_DEFAULT_FAN_MIN_PWM 0x20 /*  20% */

/* hashratio protocol package type */
#define HRTO_H1	'H'
#define HRTO_H2	'R'

#define HRTO_P_COINBASE_SIZE    (6 * 1024)
#define HRTO_P_MERKLES_COUNT    20

#define HRTO_P_COUNT            39
#define HRTO_P_DATA_LEN         (HRTO_P_COUNT - 7)

#define HRTO_DEFAULT_TIMEOUT 0x2D

#define HRTO_P_DETECT   10
#define HRTO_P_STATIC   11
#define HRTO_P_JOB_ID   12
#define HRTO_P_COINBASE 13
#define HRTO_P_MERKLES  14
#define HRTO_P_HEADER   15
#define HRTO_P_POLLING  16
#define HRTO_P_TARGET   17
#define HRTO_P_REQUIRE  18
#define HRTO_P_SET      19
#define HRTO_P_TEST     20

#define HRTO_P_ACK       21
#define HRTO_P_NAK       22
#define HRTO_P_NONCE     23
#define HRTO_P_STATUS    24
#define HRTO_P_ACKDETECT 25
#define HRTO_P_TEST_RET  26
/* hashratio protocol package type */

struct hashratio_pkg {
	uint8_t head[2];
	uint8_t type;
	uint8_t idx;
	uint8_t cnt;
	uint8_t data[32];
	uint8_t crc[2];
};
#define hashratio_ret hashratio_pkg

struct hashratio_info {
	int fd;
	int baud;
	int timeout;

	int fan_pwm;

//	int fan [HRTO_DEFAULT_MODULARS];
//	int temp[HRTO_DEFAULT_MODULARS];
	int fan;
	int temp;

	int temp_max;
	int temp_history_count;
	int temp_history_index;
	int temp_sum;
	int temp_old;

	bool first;
	bool new_stratum;

	int pool_no;
	int diff;
	
	cgtimer_t cgsent;
	int send_delay;

//	int local_works  [HRTO_DEFAULT_MODULARS];
//	int hw_works     [HRTO_DEFAULT_MODULARS];
//	int matching_work[HRTO_DEFAULT_MINERS * HRTO_DEFAULT_MODULARS];
//	int local_work   [HRTO_DEFAULT_MODULARS];
//	int hw_work      [HRTO_DEFAULT_MODULARS];

//	int  modulars  [HRTO_DEFAULT_MODULARS];
//	char mm_version[HRTO_DEFAULT_MODULARS][16];
	int local_works;
	int hw_works;
	int matching_work[HRTO_DEFAULT_MINERS];
	int local_work;
	int hw_work;
	
	char mm_version[16];
};

#define HRTO_WRITE_SIZE  (sizeof(struct hashratio_pkg))
#define HRTO_READ_SIZE   HRTO_WRITE_SIZE

#define HRTO_FTDI_READSIZE 510
#define HRTO_READBUF_SIZE  8192
/* Set latency to just less than full 64 byte packet size at 115200 baud */
#define HRTO_LATENCY 4

#define HRTO_GETS_OK       0
#define HRTO_GETS_TIMEOUT  -1
#define HRTO_GETS_RESTART  -2
#define HRTO_GETS_ERROR    -3

#define HRTO_SEND_OK    0
#define HRTO_SEND_ERROR -1

#define hashratio_open(devpath, baud, purge)  serial_open(devpath, baud, HRTO_RESET_FAULT_DECISECONDS, purge)
#define hashratio_close(fd) close(fd)

extern char *set_hashratio_fan(char *arg);

#endif /* USE_HASHRATIO */
#endif	/* _HASHRATIO_H_ */
