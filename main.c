#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/netmap_user.h>

int main() 
{
    

    struct netmap_if *nifp;
    struct nmreq req;
    int i, len;
    char *buf;

    fd = open("/dev/netmap", 0);
    strcpy(req.nr_name, "em0"); // register the interface
    ioctl(fd, NIOCREG, &req); // offset of the structure
    mem = mmap(NULL, req.nr_memsize, PROT_READ|PROT_WRITE, 0, fd, 0);
    nifp = NETMAP_IF(mem, req.nr_offset);
    for (;;) {
    	struct pollfd x[1];
    	struct netmap_ring *ring = NETMAP_RX_RING(nifp, 0);

    	x[0].fd = fd;
    	x[0].events = POLLIN;
    	poll(x, 1, 1000);
    	for ( ; ring->avail > 0 ; ring->avail--) {
    		i = ring->cur;
    		buf = NETMAP_BUF(ring, i);
    		use_data(buf, ring->slot[i].len);
    		ring->cur = NETMAP_NEXT(ring, i);
    	}
    }
}
