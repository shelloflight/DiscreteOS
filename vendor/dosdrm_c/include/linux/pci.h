#ifndef _LINUX_PCI_H
#define _LINUX_PCI_H

#include <linux/types.h>
#include <dosdrm/shim.h>

struct pci_dev {
    uint32_t dev_handle;
    uint16_t vendor;
    uint16_t device;
    uint8_t revision;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t progif;
    uint64_t bar_size[6];
};

static inline int pci_read_config_byte(const struct pci_dev *dev, int where, u8 *val) {
    return dosdrm_pci_read_config(dev->dev_handle, (uint16_t)where, 1, val);
}

static inline int pci_read_config_word(const struct pci_dev *dev, int where, u16 *val) {
    return dosdrm_pci_read_config(dev->dev_handle, (uint16_t)where, 2, val);
}

static inline int pci_read_config_dword(const struct pci_dev *dev, int where, u32 *val) {
    return dosdrm_pci_read_config(dev->dev_handle, (uint16_t)where, 4, val);
}

static inline int pci_write_config_word(const struct pci_dev *dev, int where, u16 val) {
    return dosdrm_pci_write_config(dev->dev_handle, (uint16_t)where, 2, val);
}

static inline int pci_write_config_dword(const struct pci_dev *dev, int where, u32 val) {
    return dosdrm_pci_write_config(dev->dev_handle, (uint16_t)where, 4, val);
}

#endif
