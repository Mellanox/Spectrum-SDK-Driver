/*
 * Copyright (c) 2010-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION & AFFILIATES, Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <linux/uaccess.h>

#include <linux/mlx_sx/kernel_user.h>
#include <linux/mlx_sx/cmd.h>

#include "sx.h"
#include "sx_dpt.h"
#include "ioctl_internal.h"

SX_CORE_IOCTL_ACCESS_REG_HANDLER(PSPA, ku_access_pspa_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MHSR, ku_access_mhsr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PMLP, ku_access_pmlp_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PLIB, ku_access_plib_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PCNR, ku_access_pcnr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PLPC, ku_access_plpc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PPLM, ku_access_pplm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PMPC, ku_access_pmpc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PPSC, ku_access_ppsc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PMPR, ku_access_pmpr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SBCTC, ku_access_sbctc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PELC, ku_access_pelc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PLBF, ku_access_plbf_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MSCI, ku_access_msci_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFSC, ku_access_mfsc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFSM, ku_access_mfsm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFSL, ku_access_mfsl_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PVLC, ku_access_pvlc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MCIA, ku_access_mcia_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(HCAP, ku_access_hcap_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(HDRT, ku_access_hdrt_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFCR, ku_access_mfcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(FORE, ku_access_fore_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MTBR, ku_access_mtbr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MMDIO, ku_access_mmdio_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MMIA, ku_access_mmia_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFPA, ku_access_mfpa_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFBE, ku_access_mfbe_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFBA, ku_access_mfba_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RAW, ku_access_raw_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RAW_BUFF, ku_access_reg_raw_buff);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MFM, ku_access_mfm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SSPR, ku_access_sspr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SPMCR, ku_access_spmcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MRSR, ku_access_mrsr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RGCR, ku_access_rgcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RTPS, ku_access_rtps_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RTCA, ku_access_rtca_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RUFT, ku_access_ruft_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MPSC, ku_access_mpsc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MLCR, ku_access_mlcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PPBMP, ku_access_ppbmp_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PPBMC, ku_access_ppbmc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(QPCR, ku_access_qpcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(QPEM, ku_access_qpem_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(IBSNI, ku_access_ibsni_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SLCR, ku_access_slcr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SLCR_V2, ku_access_slcr_v2_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SFN, ku_access_sfn_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SPVTR, ku_access_spvtr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SPMS, ku_access_spms_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(CWTP, ku_access_cwtp_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PFCC, ku_access_pfcc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(QPPM, ku_access_qppm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SBMM, ku_access_sbmm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SLECR, ku_access_slecr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(SPVC, ku_access_spvc_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MRRR, ku_access_mrrr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(PCMR, ku_access_pcmr_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(RDPM, ku_access_rdpm_reg);
SX_CORE_IOCTL_ACCESS_REG_HANDLER(MNVDA_NV_SWITCH_CONF, ku_access_mnvda_nv_switch_conf_reg);

const ioctl_handler_cb_t
    ioctl_reg_handler_table[CTRL_CMD_ACCESS_REG_MAX - CTRL_CMD_ACCESS_REG_MIN + 1] = {
    IOCTL_REG_HANDLER(PSPA),
    IOCTL_REG_HANDLER(MHSR),
    IOCTL_REG_HANDLER(PMLP),
    IOCTL_REG_HANDLER(PLIB),
    IOCTL_REG_HANDLER(PCNR),
    IOCTL_REG_HANDLER(PLPC),
    IOCTL_REG_HANDLER(PPLM),
    IOCTL_REG_HANDLER(PMPC),
    IOCTL_REG_HANDLER(PPSC),
    IOCTL_REG_HANDLER(PMPR),
    IOCTL_REG_HANDLER(SBCTC),
    IOCTL_REG_HANDLER(PELC),
    IOCTL_REG_HANDLER(PLBF),
    IOCTL_REG_HANDLER(MSCI),
    IOCTL_REG_HANDLER(MFSC),
    IOCTL_REG_HANDLER(MFSM),
    IOCTL_REG_HANDLER(MFSL),
    IOCTL_REG_HANDLER(PVLC),
    IOCTL_REG_HANDLER(MCIA),
    IOCTL_REG_HANDLER(HCAP),
    IOCTL_REG_HANDLER(HDRT),
    IOCTL_REG_HANDLER(MFCR),
    IOCTL_REG_HANDLER(FORE),
    IOCTL_REG_HANDLER(MTBR),
    IOCTL_REG_HANDLER(MMDIO),
    IOCTL_REG_HANDLER(MMIA),
    IOCTL_REG_HANDLER(MFPA),
    IOCTL_REG_HANDLER(MFBE),
    IOCTL_REG_HANDLER(MFBA),
    IOCTL_REG_HANDLER(RAW),
    IOCTL_REG_HANDLER(RAW_BUFF),
    IOCTL_REG_HANDLER(MFM),
    IOCTL_REG_HANDLER(SSPR),
    IOCTL_REG_HANDLER(SPMCR),
    IOCTL_REG_HANDLER(SPMS),
    IOCTL_REG_HANDLER(MRSR),
    IOCTL_REG_HANDLER(RGCR),
    IOCTL_REG_HANDLER(RTPS),
    IOCTL_REG_HANDLER(RTCA),
    IOCTL_REG_HANDLER(RUFT),
    IOCTL_REG_HANDLER(MPSC),
    IOCTL_REG_HANDLER(MLCR),
    IOCTL_REG_HANDLER(PPBMP),
    IOCTL_REG_HANDLER(PPBMC),
    IOCTL_REG_HANDLER(QPCR),
    IOCTL_REG_HANDLER(QPEM),
    IOCTL_REG_HANDLER(IBSNI),
    IOCTL_REG_HANDLER(SLCR),
    IOCTL_REG_HANDLER(SLCR_V2),
    IOCTL_REG_HANDLER(SFN),
    IOCTL_REG_HANDLER(SPVTR),
    IOCTL_REG_HANDLER(CWTP),
    IOCTL_REG_HANDLER(PFCC),
    IOCTL_REG_HANDLER(QPPM),
    IOCTL_REG_HANDLER(SBMM),
    IOCTL_REG_HANDLER(SLECR),
    IOCTL_REG_HANDLER(SPVC),
    IOCTL_REG_HANDLER(MRRR),
    IOCTL_REG_HANDLER(PCMR),
    IOCTL_REG_HANDLER(RDPM),
    IOCTL_REG_HANDLER(MNVDA_NV_SWITCH_CONF),
};
