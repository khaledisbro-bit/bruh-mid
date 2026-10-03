/* One measured number at a time, over its whole range, filtered on what the
 * plaintext has to look like.
 *
 * The key is three numbers, each a linear form mod 2^31-1 over the five numbers
 * the build measures off the host. Four of them are taken as measured and the
 * fifth is scanned. For each candidate the keystream's first 48 bytes are
 * generated and exclusive-ored into the ciphertext, and the result is counted
 * for distinct byte values. A wrong key gives uniform noise, which has about 41
 * distinct values in 48 bytes; the one piece of this file whose plaintext is
 * known has 25. Anything at or under 38 is reported and checked properly
 * afterwards with the file's own tag.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ct48.h"

#define M 2147483647ULL

static unsigned long long Si = 768435ULL, Sq = 553584ULL, SJ = 1705633901ULL,
                          Se = 1508207997ULL, SU = 1621166966ULL;
static const unsigned long long Sx = 1733248236ULL, SP = 0ULL, C1 = 1812386200ULL;

static void keyof(unsigned long long si, unsigned long long sq,
                  unsigned long long sj, unsigned long long se,
                  unsigned long long su, unsigned long long *k)
{
    k[0] = (sj*48271ULL + se*131ULL + su*17ULL + si*257ULL + sq*31ULL
            + Sx*7919ULL + SP*73ULL + C1*193ULL + 1792341575ULL) % M;
    k[1] = (se*65599ULL + su*257ULL + sj*31ULL + si*97ULL + sq*313ULL
            + Sx*131ULL + SP*40503ULL + C1*17ULL + 1733192873ULL) % M;
    k[2] = (su*31337ULL + sj*193ULL + se*73ULL + si*17ULL + sq*257ULL
            + Sx*65537ULL + SP*131ULL + C1*7919ULL + 246468262ULL) % M;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "which: Si Sq SJ Se SU\n"); return 2; }
    const char *which = argv[1];
    unsigned long long limit = (argc > 2) ? strtoull(argv[2], 0, 10) : M;
    unsigned long long v, k[3];
    unsigned char seen[256];
    long long reported = 0;
    for (v = 0; v < limit; v++) {
        if (!strcmp(which, "Si")) keyof(v, Sq, SJ, Se, SU, k);
        else if (!strcmp(which, "Sq")) keyof(Si, v, SJ, Se, SU, k);
        else if (!strcmp(which, "SJ")) keyof(Si, Sq, v, Se, SU, k);
        else if (!strcmp(which, "Se")) keyof(Si, Sq, SJ, v, SU, k);
        else keyof(Si, Sq, SJ, Se, v, k);
        unsigned long long sV = k[0], sd = k[1], sB = k[2];
        memset(seen, 0, sizeof seen);
        int distinct = 0, i;
        for (i = 0; i < 48; i++) {
            unsigned long long a = sV, b = sd, c = sB, j = (unsigned long long)i + 1ULL;
            sV = (a*48271ULL + b*131ULL   + j*7919ULL   + 17ULL) % M;
            sd = (b*65599ULL + c*257ULL   + j*40503ULL  + 31ULL) % M;
            sB = (c*31337ULL + a*193ULL   + j*104729ULL + 73ULL) % M;
            unsigned char ks = (unsigned char)((sV & 255) ^ (sd & 255) ^ (sB & 255));
            unsigned char pt = (unsigned char)(CT[i] ^ ks);
            if (!seen[pt]) { seen[pt] = 1; distinct++; }
        }
        if (distinct <= 34) {
            printf("%s=%llu distinct=%d key=%llu,%llu,%llu\n",
                   which, v, distinct, k[0], k[1], k[2]);
            if (++reported > 200000) { printf("too many; stopping\n"); break; }
        }
        if ((v & 0xFFFFFFFULL) == 0) { fprintf(stderr, "  %s at %llu\n", which, v); fflush(stderr); }
    }
    fprintf(stderr, "%s done, %lld candidate(s)\n", which, reported);
    return 0;
}
