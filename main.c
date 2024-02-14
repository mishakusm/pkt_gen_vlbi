#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/netmap_user.h>

int main() {
    struct nmreq req;
    int fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/netmap");
        exit(1);
    }

    memset(&req, 0, sizeof(req));
    strcpy(req.nr_name, "netmap:em0"); // замените "em0" на имя вашего сетевого устройства
    req.nr_version = NETMAP_API;
    ioctl(fd, NIOCGINFO, &req);

    struct nm_desc *nmd = nm_open(req.nr_name, NULL, 0, NULL);
    if (nmd == NULL) {
        perror("Failed to open netmap device");
        exit(1);
    }

    char buf[2048]; // буфер для пакета
    memset(buf, 0, sizeof(buf));

    struct netmap_ring *txring = NETMAP_TXRING(nmd->nifp, nmd->cur_tx_ring);
    uint32_t txslot = txring->cur;
    struct netmap_slot *slot = &txring->slot[txslot];

    // Заполните буфер пакета данными

    slot->len = sizeof(buf); // Установите длину пакета
    memcpy(NETMAP_BUF(txring, slot->buf_idx), buf, sizeof(buf));

    slot->flags |= NS_REPORT; // Установите флаг NS_REPORT для отправки пакета

    txring->head = txring->cur = nm_ring_next(txring, txring->cur);

    ioctl(fd, NIOCTXSYNC, NULL); // Синхронизация передачи пакета

    nm_close(nmd);
    close(fd);

    return 0;
}
