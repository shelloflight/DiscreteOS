#ifndef _AMDGPU_PSP_SMU_H
#define _AMDGPU_PSP_SMU_H

#include <linux/types.h>
#include <linux/dma-mapping.h>

/* PSP GFX command IDs (matching upstream psp_gfx_if.h). */
#define PSP_CMD_LOAD_TA                    0x00000001u
#define PSP_CMD_UNLOAD_TA                  0x00000002u
#define PSP_CMD_SETUP_TMR                  0x00000005u
#define PSP_CMD_LOAD_IP_FW                 0x00000006u
#define PSP_CMD_DESTROY_TMR                0x00000007u
#define PSP_CMD_SAVE_RESTORE_IP_FW         0x00000008u
#define PSP_CMD_LOAD_TOC                   0x00000011u
#define PSP_CMD_AUTOLOAD_RLC               0x00000021u

/* PSP GFX firmware type tags for PSP_CMD_LOAD_IP_FW. */
#define PSP_GFX_FW_TYPE_SMU                0x03u
#define PSP_GFX_FW_TYPE_SDMA0              0x04u
#define PSP_GFX_FW_TYPE_CP_PFP             0x06u
#define PSP_GFX_FW_TYPE_CP_ME              0x07u
#define PSP_GFX_FW_TYPE_CP_MEC1            0x08u
#define PSP_GFX_FW_TYPE_RLC_G              0x0Bu
#define PSP_GFX_FW_TYPE_DMUB               0x19u
#define PSP_GFX_FW_TYPE_CP_MES             0x22u
#define PSP_GFX_FW_TYPE_IMU_I              0x2Du

/* SMU / PMFW PPSMC message IDs (verified from smu_v13_0_0_ppsmc.h & smu_v14_0_2_ppsmc.h). */
#define PPSMC_MSG_TestMessage              0x01u
#define PPSMC_MSG_GetSmuVersion            0x02u
#define PPSMC_MSG_TransferTableSmu2Dram    0x12u
#define PPSMC_MSG_SetHardMinByFreq         0x1Bu
#define PPSMC_MSG_PrepareMp1ForUnload      0x2Eu
#define PPSMC_Result_OK                    0x01u

/* SMU clock IDs for SetHardMinByFreq. */
enum amdgpu_smu_clk {
    AMDGPU_SMU_CLK_GFXCLK = 0,
    AMDGPU_SMU_CLK_SOCCLK = 1,
    AMDGPU_SMU_CLK_UCLK   = 2,
    AMDGPU_SMU_CLK_FCLK   = 3,
    AMDGPU_SMU_CLK_DCEFCLK = 4,
    AMDGPU_SMU_CLK_DISPCLK = 5,
    AMDGPU_SMU_CLK_PIXCLK  = 6,
    AMDGPU_SMU_CLK_PHYCLK  = 7,
    AMDGPU_SMU_CLK_DTBCLK  = 8,
    AMDGPU_SMU_CLK_DPPCLK  = 9,
};

struct amdgpu_psp_state {
    bool initialized;
    bool sos_alive;
    bool tmr_ready;
    u32 fw_version;
    u32 loaded_fw_mask;
    struct dosdrm_dma_buf cmd_buf;
};

struct amdgpu_smu_state {
    bool initialized;
    bool pmfw_alive;
    u32 smu_version;
    u32 min_dispclk_mhz;
    u32 min_dppclk_mhz;
    u32 min_dcfclk_mhz;
    u32 min_dtbclk_mhz;
    u32 min_uclk_mhz;
    u32 min_socclk_mhz;
};

struct amdgpu_device;

int amdgpu_psp_init(struct amdgpu_device *adev);
int amdgpu_psp_load_ip_fw(struct amdgpu_device *adev, u32 psp_fw_type, u64 dma_addr, u32 size_bytes);
void amdgpu_psp_fini(struct amdgpu_device *adev);

int amdgpu_smu_init(struct amdgpu_device *adev);
int amdgpu_smu_send_msg(struct amdgpu_device *adev, u32 msg, u32 param, u32 *resp_out);
int amdgpu_smu_set_display_clocks(
    struct amdgpu_device *adev,
    u32 dispclk_mhz,
    u32 dppclk_mhz,
    u32 dcfclk_mhz,
    u32 dtbclk_mhz,
    u32 uclk_mhz
);
int amdgpu_smu_suspend(struct amdgpu_device *adev);
int amdgpu_smu_resume(struct amdgpu_device *adev);

#endif
