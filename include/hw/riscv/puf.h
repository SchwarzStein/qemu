/*
 * PUF
 */

#ifndef HW_PUF_H
#define HW_PUF_H

#define TYPE_PUF "riscv.puf"

#define PUF(obj) \
    OBJECT_CHECK(PUFState, (obj), TYPE_PUF)

typedef struct PUFState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    MemoryRegion mmio;
    uint64_t persona;
    uint64_t puf_select;
    uint32_t puf_disable;
} PUFState;

DeviceState *puf_create(hwaddr addr, hwaddr size, uint64_t persona);

enum {
    PUF_SELECT     = 0x00,
    PUF_READOUT    = 0x08,
    PUF_DISABLE    = 0x10
};

#endif
