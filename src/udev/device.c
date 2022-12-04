
#include "alloc-util.h"
#include "device.h"

int device_new_from_ifname(sd_device **ret, char *ifname) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _auto_cleanup_ char *path = NULL;
        int r;

        asprintf(&path, "/sys/class/net/%s", ifname);
        r = sd_device_new_from_syspath(&dev, path);
        if (r < 0)
                return r;

        *ret = steal_pointer(dev);
        return 0;
}
