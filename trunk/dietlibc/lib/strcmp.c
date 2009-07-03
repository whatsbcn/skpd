/* fast strcmp -- Copyright (C) 2003 Thomas M. Ogrisegg <tom@hi-tek.fnord.at> */
#include <string.h>
#include "dietfeatures.h"
#include "dietstring.h"

int
strcmp (const char *s1, const char *s2)
{
#ifdef WANT_SMALL_STRING_ROUTINES
    while (*s1 && *s1 == *s2)
        s1++, s2++;
    return (*s1 - *s2);
#else
    const unsigned long *lx1, *lx2;
    unsigned long   l1, l2;
    int             tmp;

    if (UNALIGNED(s1, s2)) {
        while (*s1 && *s1 == *s2) s1++, s2++;
        return (*s1 - *s2);
    }

    if ((tmp = STRALIGN(s1)))
        for (; tmp--; s1++, s2++)
            if (!*s1 || *s1 != *s2)
                return (*s1 - *s2);

    lx1 = (unsigned long *) s1;
    lx2 = (unsigned long *) s2;

    while (1) {
        l1 = *lx1++;
        l2 = *lx2++;
        if ((((l1 - MKW(0x1)) & ~l1) & MKW(0x80)) ||
            ((((l2 - MKW(0x1)) & ~l2) & MKW(0x80))) || l1 != l2) {
            unsigned char c1, c2;
            while (1) {
                c1 = l1 & 0xff;
                c2 = l2 & 0xff;
                if (!c1 || c1 != c2)
                    return (c1 - c2);
                l1 >>= 8;
                l2 >>= 8;
            }
        }
    }
#endif
}

int strcoll(const char *s,const char* t)       __attribute__((weak,alias("strcmp")));
