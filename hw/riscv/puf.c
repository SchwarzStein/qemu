/*
 * PUF
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/sysbus.h"
#include "target/riscv/cpu.h"
#include "hw/riscv/puf.h"
#include "qemu/timer.h"

/* CPU wants to read the puf */
static uint64_t puf_read(void *opaque, hwaddr addr, unsigned size)
{
    PUFState *puf = opaque;

    /* reads must be 8 byte aligned words */
    if ((addr & 0x7) != 0 || size != 8) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "clint: invalid read size %u: 0x%" HWADDR_PRIx "\n", size, addr);
        return 0L;
    }

    if (addr == PUF_SELECT) {
        /* puf_select */
        return puf->puf_select;
    } else if (addr == PUF_READOUT) {
        /* puf_readout */
        return 0xDEADBEEFL; /* TODO: implement some function of persona and puf_select and puf_disable[0]*/
    } else if (addr == PUF_DISABLE) {
        /* puf_disable */
        return puf->puf_disable;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
            "clint: invalid read: 0x%" HWADDR_PRIx "\n", addr);
    }

    return 0L;
}

/* CPU wrote to the puf */
static void puf_write(void *opaque, hwaddr addr, uint64_t value,
        unsigned size)
{
    PUFState *puf = opaque;

    /* writes must be 4 byte aligned words */
    if ((addr & 0x7) != 0 || size != 8) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "clint: invalid write size %u: 0x%" HWADDR_PRIx "\n", size, addr);
        return;
    }

    if ((int64_t) addr >= (int64_t) PUF_SELECT) {
        /* puf_select */
        puf->puf_select = value;
        return;
    } else if (addr >= PUF_READOUT) {
        /* puf_readout writes are ignored */
        return;
    } else if (addr == PUF_DISABLE) {
        /* puf_disable is one bit long, and cannot be cleared */
        puf->puf_disable = (puf->puf_disable | value) & 0x1;
        return;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
            "clint: invalid write: 0x%" HWADDR_PRIx "\n", addr);
    }
}

static const MemoryRegionOps puf_ops = {
    .read = puf_read,
    .write = puf_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8
    }
};

static Property puf_properties[] = {
    DEFINE_PROP_UINT64("persona", PUFState, persona, 0),
    DEFINE_PROP_UINT64("puf_select", PUFState, puf_select, 0),
    DEFINE_PROP_UINT32("puf_disable", PUFState, puf_disable, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void puf_realize(DeviceState *dev, Error **errp)
{
    PUFState *s = PUF(dev);
    memory_region_init_io(&s->mmio, OBJECT(dev), &puf_ops, s,
                          TYPE_PUF, 0x20);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void puf_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = puf_realize;
    dc->props = puf_properties;
}

static const TypeInfo puf_info = {
    .name          = TYPE_PUF,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PUFState),
    .class_init    = puf_class_init,
};

static void puf_register_types(void)
{
    type_register_static(&puf_info);
}

type_init(puf_register_types)

/*
 * Create PUF device.
 */
DeviceState *puf_create(hwaddr addr, hwaddr size, uint64_t persona)
{
    DeviceState *dev = qdev_create(NULL, TYPE_PUF);
    qdev_prop_set_uint64(dev, "persona", persona);
    qdev_prop_set_uint64(dev, "puf_select", 0);
    qdev_prop_set_uint32(dev, "puf_disable", false);
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
    return dev;
}
