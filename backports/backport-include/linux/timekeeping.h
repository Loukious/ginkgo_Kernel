#ifndef __BACKPORT_TIMEKEEPING_H
#define __BACKPORT_TIMEKEEPING_H
#include <linux/version.h>
#include <linux/types.h>
#include <linux/ktime.h>

#include_next <linux/timekeeping.h>

#if LINUX_VERSION_IS_LESS(5,0,0)
static inline u64 ktime_get_boottime_ns(void)
{
	return ktime_get_boot_ns();
}
#endif /* < 5.0 */

#if LINUX_VERSION_IS_LESS(4,18,0)
static inline void ktime_get_raw_ts64(struct timespec64 *ts)
{
	getrawmonotonic64(ts);
}
#endif /* < 4.18 */

#if LINUX_VERSION_IS_LESS(4,18,0)
extern time64_t ktime_get_boottime_seconds(void);
#endif /* < 4.18 */

#endif /* __BACKPORT_TIMEKEEPING_H */
