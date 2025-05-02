/*
 * detector -- detection unit that searches for attacks
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
#include <string.h>

#include "hexpads.h"
#include "detector.h"
#include "mitigator.h"

/**
 * detector - scan all processes and search for attacks
 */

#define NUM_BINS 100

double get_entropy(long long data[NR_SAMPLES]) {
    if (data == NULL) return 0.0;

    // Step 1: Find min and max
    long long min_value = data[0], max_value = data[0];
    for (int i = 0; i < NR_SAMPLES; i++) {
        if (data[i] < min_value) min_value = data[i];
        if (data[i] > max_value) max_value = data[i];
    }

    if (min_value == max_value) return 0.0; // No variation => entropy = 0

    // Step 2: Initialize bins
    int bins[NUM_BINS] = {0};

    // Step 3: Bin the data
    for (int i = 0; i < NR_SAMPLES; i++) {
        int bin_index = (int)((double)(data[i] - min_value) / (max_value - min_value) * (NUM_BINS - 1));
        bins[bin_index]++;
    }

    // Step 4: Compute entropy
    double entropy = 0.0;
    double total = (double) NR_SAMPLES;
    for (int i = 0; i < NUM_BINS; i++) {
        if (bins[i] > 0) {
            double p = bins[i] / total;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}



//  double get_entropy(long long data[NR_SAMPLES]) {
//   if (data == NULL) return 0.0;

//   // Step 1: Find min and max
//   long long min_value = data[0], max_value = data[0];
//   for (int i = 0; i < NR_SAMPLES; i++) {
//       if (data[i] < min_value) min_value = data[i];
//       if (data[i] > max_value) max_value = data[i];
//   }

//   // Step 2: Allocate frequency array
//   int range = max_value - min_value + 1;
//   int *freq = calloc(range, sizeof(int));
//   if (!freq) {
//       perror("calloc failed");
//       return 0.0;
//   }

//   // Step 3: Count frequencies
//   for (int i = 0; i < NR_SAMPLES; i++) {
//       freq[data[i] - min_value]++;
//   }

//   // Step 4: Compute entropy
//   double entropy = 0.0;
//   double total = (double) NR_SAMPLES;
//   for (int i = 0; i < range; i++) {
//       if (freq[i] > 0) {
//           double p = freq[i] / total;
//           entropy -= p * log2(p);
//       }
//   }

//   free(freq);
//   return entropy;
// }



void detector(struct proc *procs) {
  struct proc *loc = procs;
  int sender_pid  = -1;
  double sender_entropy = 0.0;
  // iterate over all running processes
  while (loc != NULL) {
  //  printf("[i] PID %d, '%s' (%d)\n", loc->pid, loc->cmd, loc->status);
    if (loc->status == STATUS_READY) {
      // printf("%s\n",loc->cmd);
      long long icount = 0, cmiss = 0, caccess = 0;
      long minflt;
      long long misses[NR_SAMPLES];
      if(loc->psample == NULL) {
        loc = loc->next;
        continue;
      }
      for (int i = 0; i<NR_SAMPLES; ++i) {
        icount += loc->psample->instr[i];
        caccess += loc->psample->cache_access[i];
        cmiss += loc->psample->cache_miss[i];
        minflt += loc->psample->minflt[i];
        misses[i] = loc->psample->cache_miss[i];
      }
     
      // for(int i=0; i<NR_SAMPLES; ++i) {
      //   printf("%lld ", misses[i]);
      // }
     // printf("\n");
      double entropy = get_entropy(misses);
      icount /= NR_SAMPLES;
      caccess /= NR_SAMPLES;
      cmiss /= NR_SAMPLES;
      minflt /= NR_SAMPLES;
      int ringloc = loc->psample->ringloc;
      int old = (ringloc - 1 + NR_SAMPLES) % NR_SAMPLES;

      double pmissrate = ((double)loc->psample->minflt[ringloc])/((double)loc->psample->instr[ringloc]);
      double fltrate = (double)loc->psample->minflt[ringloc] / ((double)loc->psample->minflt[old] + 1);
      int lasttwo = loc->psample->minflt[ringloc] + loc->psample->minflt[old] ;
      //printf("[i] PID %d executed %lld instructions with %lld/%lld cache misses (%f ratio), %lu page faults (on average).\n", loc->pid, icount, cmiss, caccess, (double)cmiss/(double)caccess, minflt);

      /* cache attack detection */
      //print entropy
      
    //  printf("[i] PID %d executed %lld instructions with %lld/%lld cache misses (%f ratio), %lu page faults (on average).\n", loc->pid, icount, cmiss, caccess, (double)cmiss/(double)caccess, minflt);
      double cmissrate = (double)cmiss/(double)caccess;

      // loge("PID: %d, '%s', (%f missrate, %lld misses) entropy %f pmissrate %f\n", loc->pid, loc->cmd, cmissrate, cmiss, entropy, pmissrate);
    //  if(cmissrate>0.7){
      //  printf("[%d] PID had %f entropy %s\n", loc->pid,entropy,loc->cmd);
    //    }

    if (cmissrate > 0.7 && cmiss > 100000 && fltrate < 0.01 && entropy > 0.5 && entropy < 1.05) {
      loge("[i] Potential streamline attack detected! PID: %d, '%s', (%f missrate, %lld misses) entropy %f pmissrate %f\n", loc->pid, loc->cmd, cmissrate, cmiss, entropy, pmissrate);
      sender_pid = loc->pid;
      sender_entropy = entropy;
      // printf("entropy: %f",entropy);
      //  mitigate(loc);
    }

      else if (cmissrate > 0.7 && cmiss > 100000 && fltrate < 0.01 && (entropy<0.5|| entropy>1.05)) {
        loge("[i] Potential cache attack detected! PID: %d, '%s', (%f missrate, %lld misses) entropy %f pmissrate %f\n", loc->pid, loc->cmd, cmissrate, cmiss, entropy, pmissrate);
        // printf("entropy: %f",entropy);
        //  mitigate(loc);
      }
      else if(sender_pid!=-1 && cmissrate > 0.7 && (sender_entropy-entropy)<0.5) {
        loge("[i] Potential streamline attack RECEIVER detected! PID: %d, '%s', (%f missrate, %lld misses) entropy %f pmissrate %f\n", loc->pid, loc->cmd, cmissrate, cmiss, entropy, pmissrate);
      }
      /* CAIN detection */
      if (
        (
          (fltrate > 2.0 
          && loc->psample->minflt[ringloc] > 100000
          && loc->psample->cache_miss[ringloc] > 10000
          && pmissrate > 0.001
          ) 
          ||
          ( lasttwo > 256000 )
        ) 
        ) {
        loge("[i] Potential CAIN detected. PID: %d, '%s' (page misses: %ld/%ld, (%f) cache misses: %lld, cache miss rate: %f, page fault miss rate: %f).\n", loc->pid, loc->cmd, loc->psample->minflt[loc->psample->ringloc], loc->psample->minflt[old], fltrate, loc->psample->cache_miss[loc->psample->ringloc], cmissrate, pmissrate);
        mitigate(loc);
      }
      //if (strncmp(loc->cmd, "anteater", 8) == 0) {
      //  log("[i] CAIN metrics: %d - %ld/%ld (%f) %lld cmr %f pmr %f\n", loc->pid, loc->psample->minflt[ringloc], loc->psample->minflt[old], fltrate, loc->psample->cache_miss[ringloc], cmissrate, pmissrate);
      //}
    } // STATUS_READY
    loc = loc->next;
  } // loop over all processes
}
