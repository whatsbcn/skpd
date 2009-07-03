#ifndef _SYS_PRCTL_H
#define _SYS_PRCTL_H

#include <sys/cdefs.h>

/* Values to pass as first argument to prctl() */

#define PR_SET_PDEATHSIG  1  /* Second arg is a signal */
#define PR_GET_PDEATHSIG  2  /* Second arg is a ptr to return the signal */

/* Get/set current->mm->dumpable */
#define PR_GET_DUMPABLE   3
#define PR_SET_DUMPABLE   4

/* Get/set unaligned access control bits (if meaningful) */
#define PR_GET_UNALIGN	  5
#define PR_SET_UNALIGN	  6
# define PR_UNALIGN_NOPRINT	1	/* silently fix up unaligned user accesses */
# define PR_UNALIGN_SIGBUS	2	/* generate SIGBUS on unaligned user access */

/* Get/set whether or not to drop capabilities on setuid() away from uid 0 */
#define PR_GET_KEEPCAPS   7
#define PR_SET_KEEPCAPS   8

/* Get/set floating-point emulation control bits (if meaningful) */
#define PR_GET_FPEMU  9
#define PR_SET_FPEMU 10
# define PR_FPEMU_NOPRINT	1	/* silently emulate fp operations accesses */
# define PR_FPEMU_SIGFPE	2	/* don't emulate fp operations, send SIGFPE instead */

/* Get/set floating-point exception mode (if meaningful) */
#define PR_GET_FPEXC	11
#define PR_SET_FPEXC	12
# define PR_FP_EXC_SW_ENABLE	0x80	/* Use FPEXC for FP exception enables */
# define PR_FP_EXC_DIV		0x010000	/* floating point divide by zero */
# define PR_FP_EXC_OVF		0x020000	/* floating point overflow */
# define PR_FP_EXC_UND		0x040000	/* floating point underflow */
# define PR_FP_EXC_RES		0x080000	/* floating point inexact result */
# define PR_FP_EXC_INV		0x100000	/* floating point invalid operation */
# define PR_FP_EXC_DISABLED	0	/* FP exceptions disabled */
# define PR_FP_EXC_NONRECOV	1	/* async non-recoverable exc. mode */
# define PR_FP_EXC_ASYNC	2	/* async recoverable exception mode */
# define PR_FP_EXC_PRECISE	3	/* precise exception mode */

/* Get/set whether we use statistical process timing or accurate timestamp
 * based process timing */
#define PR_GET_TIMING   13
#define PR_SET_TIMING   14
# define PR_TIMING_STATISTICAL  0       /* Normal, traditional,
                                                   statistical process timing */
# define PR_TIMING_TIMESTAMP    1       /* Accurate timestamp based
                                                   process timing */

#define PR_SET_NAME    15		/* Set process name */
#define PR_GET_NAME    16		/* Get process name */

/* Get/set process endian */
#define PR_GET_ENDIAN	19
#define PR_SET_ENDIAN	20
# define PR_ENDIAN_BIG		0
# define PR_ENDIAN_LITTLE	1	/* True little endian mode */
# define PR_ENDIAN_PPC_LITTLE	2	/* "PowerPC" pseudo little endian */


__BEGIN_DECLS

int prctl(int option, unsigned long arg2, ...) __THROW;

__END_DECLS

#endif
