/*
 * $Id: evtest.c,v 1.23 2005/02/06 13:51:42 vojtech Exp $
 *
 *  Copyright (c) 1999-2000 Vojtech Pavlik
 *
 *  Event device test program
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 * 
 * Should you need to contact me, the author, you can do so either by
 * e-mail - mail your message to <vojtech@ucw.cz>, or by paper mail:
 * Vojtech Pavlik, Simunkova 1594, Prague 8, 182 00 Czech Republic
 */

#include <stdint.h>

#include <linux/input.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>

#include "keymap.h"
#include "vjoy_event_net.hpp"

namespace vjn = vjoy_event_net;

#define PORT 63245
#define BUF_SIZE (1024*1024)
#define INP_EVE_LEN 64

#ifndef EV_SYN
#define EV_SYN 0
#endif

#define BITS_PER_LONG (sizeof(long) * 8)
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)
#define OFF(x)  ((x)%BITS_PER_LONG)
#define BIT(x)  (1UL<<OFF(x))
#define LONG(x) ((x)/BITS_PER_LONG)
#define test_bit(bit, array)	((array[LONG(bit)] >> OFF(bit)) & 1)

int main (int argc, char **argv)
{
	int fd, rd, i, j, k;
	struct input_event ev[INP_EVE_LEN];
	int version;
	unsigned short id[4];
	unsigned long bit[EV_MAX][NBITS(KEY_MAX)];
	char name[256] = "Unknown";
	int abs[5];
	int sock = 0, valread, client_fd;
    struct sockaddr_in serv_addr;
	vjn::ScanKeyT scan_keys[KEY_CNT];
	vjn::ScanAbsT scan_abs[KEY_CNT];
	int total_keys = 0;
	int total_abs = 0;
	uint32_t cntr = 0;
	memset(scan_keys, sizeof(scan_keys), 0xFF);
	memset(scan_abs, sizeof(scan_keys), 0xFF);

	//evtest
	if (argc < 2) {
		printf("Usage: evtest /dev/input/eventX\n");
		printf("Where X = input device number\n");
		return 1;
	}

	if ((fd = open(argv[argc - 1], O_RDONLY)) < 0) {
		perror("evtest");
		return 1;
	}

	if (ioctl(fd, EVIOCGVERSION, &version)) {
		perror("evtest: can't get version");
		return 1;
	}

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
 
	//socket
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "192.168.35.111", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((client_fd
         = connect(sock, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

	//evtest
	printf("Input driver version is %d.%d.%d\n",
		version >> 16, (version >> 8) & 0xff, version & 0xff);

	ioctl(fd, EVIOCGID, id);
	printf("Input device ID: bus 0x%x vendor 0x%x product 0x%x version 0x%x\n",
		id[ID_BUS], id[ID_VENDOR], id[ID_PRODUCT], id[ID_VERSION]);

	ioctl(fd, EVIOCGNAME(sizeof(name)), name);
	printf("Input device name: \"%s\"\n", name);

	memset(bit, 0, sizeof(bit));
	ioctl(fd, EVIOCGBIT(0, EV_MAX), bit[0]);
	printf("Supported events:\n");

	for (i = 0; i < EV_MAX; i++)
	{
		if (test_bit(i, bit[0])) {
			printf("  Event type %d (%s)\n", i, events[i] ? events[i] : "?");
			if (!i) continue;
			ioctl(fd, EVIOCGBIT(i, KEY_MAX), bit[i]);
			for (j = 0; j < KEY_MAX; j++) 
				if (test_bit(j, bit[i])) {
					printf("    Event code %d (%s)\n", j, names[i] ? (names[i][j] ? names[i][j] : "?") : "?");
					if (i == EV_ABS) {
						ioctl(fd, EVIOCGABS(j), abs);
						for (k = 0; k < 5; k++)
							if ((k < 3) || abs[k])
								printf("      %s %6d\n", absval[k], abs[k]);
						scan_abs[total_abs].code = j;
						total_abs++;
					}
					else if (i == EV_KEY) {
						scan_keys[total_keys].code = j;
						total_keys++;
					}
				}
		}
	}

	printf("Testing ... (interrupt to exit)\n");

	fd_set set;
	struct timeval timeout;
	int rv;

	while (1) {
		char tx_buffer[BUF_SIZE];
		int tx_len = 0;

		int key_data_size = 0;
		char * key_ptr = &tx_buffer[sizeof(vjn::HeaderNetT)];
		int key_tx_len = 0;

		//Perform a key scan before waiting for data
		unsigned long keys[NBITS(KEY_MAX)];
		memset(keys, 0, sizeof(keys));
		ioctl(fd, EVIOCGKEY(KEY_MAX), keys);
		for (i = 0; i < total_keys; i++) {
			int32_t new_val = test_bit(scan_keys[i].code, keys);
			scan_keys[i].value = new_val;
			//Perform inline packing to tx buffer
			ScanKeyDump(scan_keys[i], *(static_cast<vjn::ScanKeyNetT *>(static_cast<void *>(key_ptr))));
			key_ptr = &key_ptr[sizeof(vjn::ScanKeyNetT)];
			key_data_size += sizeof(vjn::ScanKeyNetT);
		}

		if (key_data_size > 0){
			//Pass data ptr where data is already loaded to skip packing
			key_tx_len = vjn::PackData(&tx_buffer[tx_len], BUF_SIZE, cntr, vjn::NetModeT_SCAN_KEY, &tx_buffer[tx_len + sizeof(vjn::HeaderNetT)], key_data_size);
			tx_len += key_tx_len;
		}

		int abs_data_size = 0;
		char * abs_ptr = &tx_buffer[tx_len + sizeof(vjn::HeaderNetT)];
		int abs_tx_len = 0;

		//Performa a scan of absolute values
		for (i = 0; i < total_abs; i++) {
			ioctl(fd, EVIOCGABS(scan_abs[i].code), abs);
			scan_abs[i].value = abs[0];
			ScanAbsDump(scan_abs[i], *(static_cast<vjn::ScanAbsNetT *>(static_cast<void *>(abs_ptr))));
			abs_ptr = &abs_ptr[sizeof(vjn::ScanAbsNetT)];
			abs_data_size += sizeof(vjn::ScanAbsNetT);
		}

		if (abs_data_size > 0){
			abs_tx_len = vjn::PackData(&tx_buffer[tx_len], BUF_SIZE, cntr, vjn::NetModeT_SCAN_ABS, &tx_buffer[tx_len + sizeof(vjn::HeaderNetT)], abs_data_size);
			tx_len += abs_tx_len;
		}

		int data_size = 0;
		char * data_ptr = &tx_buffer[tx_len + sizeof(vjn::HeaderNetT)];
		int data_tx_len = 0;

		FD_ZERO(&set); /* clear the set */
		FD_SET(fd, &set); /* add our file descriptor to the set */
		timeout.tv_sec = 0;
		timeout.tv_usec = 50000;

		rv = select(fd + 1, &set, NULL, NULL, &timeout);
		if(rv == -1){
			perror("select"); /* an error accured */
			break;
		}
		else if(rv == 0){
			//printf("timeout"); /* a timeout occured */
		}
		else{
			rd = read(fd, ev, sizeof(struct input_event) * INP_EVE_LEN);

			if (rd < (int) sizeof(struct input_event)) {
				printf("yyy\n");
				perror("\nevtest: error reading");
				return 1;
			}

			for (i = 0; i < rd / sizeof(struct input_event); i++){

				vjn::InputEventT event_data;
				event_data.tv_sec = ev[i].time.tv_sec;
				event_data.tv_usec = ev[i].time.tv_usec;
				event_data.type = ev[i].type;
				event_data.code = ev[i].code;
				event_data.value = ev[i].value;
				EventDump(event_data, *(static_cast<vjn::InputEventNetT *>(static_cast<void *>(data_ptr))));
				data_ptr = &data_ptr[sizeof(vjn::InputEventNetT)];
				data_size += sizeof(vjn::InputEventNetT);

				if (ev[i].type == EV_SYN) {
					printf("Event: time %ld.%06ld, -------------- %s ------------\n",
						ev[i].time.tv_sec, ev[i].time.tv_usec, ev[i].code ? "Config Sync" : "Report Sync" );
				} else if (ev[i].type == EV_MSC && (ev[i].code == MSC_RAW || ev[i].code == MSC_SCAN)) {
					printf("Event: time %ld.%06ld, type %d (%s), code %d (%s), value %02x\n",
						ev[i].time.tv_sec, ev[i].time.tv_usec, ev[i].type,
						events[ev[i].type] ? events[ev[i].type] : "?",
						ev[i].code,
						names[ev[i].type] ? (names[ev[i].type][ev[i].code] ? names[ev[i].type][ev[i].code] : "?") : "?",
						ev[i].value);
				} else {
					printf("Event: time %ld.%06ld, type %d (%s), code %d (%s), value %d\n",
						ev[i].time.tv_sec, ev[i].time.tv_usec, ev[i].type,
						events[ev[i].type] ? events[ev[i].type] : "?",
						ev[i].code,
						names[ev[i].type] ? (names[ev[i].type][ev[i].code] ? names[ev[i].type][ev[i].code] : "?") : "?",
						ev[i].value);
				}	
			}
		}
		if(data_size > 0){
			data_tx_len = vjn::PackData(&tx_buffer[tx_len], BUF_SIZE, cntr, vjn::NetModeT_INPUT_EVENT, &tx_buffer[tx_len + sizeof(vjn::HeaderNetT)], data_size);
			tx_len += data_tx_len;
		}
		if (tx_len > 0){
			send(sock, tx_buffer, tx_len, 0);
		}
	}

	// closing the connected socket
    close(client_fd);
    return 0;
}

