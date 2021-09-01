#ifndef __NOW_H
#define __NOW_H

/* USAGE:
 * now() : # of seconds (monotonic), for timestamps
 *
 * for(;;) {
 *   int nfd = poll(..., ...., ms_to_nexttick());
 *   if (nfd == 0) {
 *     time_t newnow = tick();
 *     //// clean actions
 *     continue
 *   }
 */

time_t now(void);
time_t tick(void);
long ms_to_nexttick(void);

#endif
