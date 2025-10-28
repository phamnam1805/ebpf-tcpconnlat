#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>
#include "tcpconnlat.h"

#define PRINT_FIELD(name) \
    printf("%-12s offset=%-3zu size=%-3zu\n", #name, offsetof(struct event, name), sizeof(((struct event *)0)->name))

int main(void) {
    printf("Struct event layout (total size = %zu bytes):\n", sizeof(struct event));
    printf("--------------------------------------------------\n");

    PRINT_FIELD(saddr_v4);
    PRINT_FIELD(saddr_v6);
    PRINT_FIELD(daddr_v4);
    PRINT_FIELD(daddr_v6);
    PRINT_FIELD(comm);
    PRINT_FIELD(delta_us);
    PRINT_FIELD(ts_us);
    PRINT_FIELD(tgid);
    PRINT_FIELD(af);
    PRINT_FIELD(lport);
    PRINT_FIELD(dport);

    return 0;
}