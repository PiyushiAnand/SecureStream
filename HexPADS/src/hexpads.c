/*
 * pmon -- performance counter based process monitoring and IDS
 * Copyright (C) 2015 Mathias Payer <mathias.payer@nebelwelt.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hexpads.h"

#include "detector.h"
#include "readperfctrs.h"
#include "readproc.h"

struct proc *procs = NULL;

int main(int argc, char *argv[]) {
  loge("[+] Initializing process list and performance counters\n");
  
  while (1) {
    /* update process list */
    procs = proc_scan(procs);

    /* update/set performance counters */
    perfctr_scan(procs);

    /* match signatures */
    detector(procs);

    /* wait for next iteration */
    sleep(SLEEP_TIME);
  }
  return 0;  
}
