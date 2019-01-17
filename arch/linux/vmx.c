#include "vmx.h"

static DEFINE_PER_CPU(vmcs_t *, vmxarea);
static vmcs_config_t vmcs_config;
vmx_capability_t _vmx_capability;

/**
 * @brief Enables VMX on every logical core with an appropriate
 *  configuration.
 *
 * @return __init init_vmx Status code.
 */
__init int init_vmx(void) {
  int lcpu; /* logical cpu identifier */

  /* Ensure the CPU supports VT-x */
  if (!cpu_has_vmx()) {
    glog(KERN_ERR, "CPU does not support VT-x");
    return -EIO;
  }

  if (setup_vmcs_config(&vmcs_config) < 0)
    return -EIO;

  if (!cpu_has_vmx_vpid()) {
    glog(KERN_ERR, "CPU does not support required feature: 'vpid'");
    return -EIO;
  }

  if (!cpu_has_vmx_ept()) {
    glog(KERN_ERR, "CPU does not support required feature: 'ept'");
    return -EIO;
  }

  /* Check it's possible to syscall & sysret */
  if (!_vmx_capability.has_load_efer) {
    glog(KERN_ERR, "RFER register modification is required");
    return -EIO;
  }

  /* Allocate vmxon_regions */
  for_each_possible_cpu(lcpu) {
    vmcs_t *vmxon_reg = __vmx_alloc_vmcs(lcpu);
    
    if (!vmxon_reg) {
      return -ENOMEM;
    }

    per_cpu(vmxarea, lcpu) = vmxon_reg;
  }

  if (on_each_cpu((void *)enable_vmx, NULL, 1)) {
    glog(KERN_ERR, "Timeout waiting for VMX to be enabled.");
  }

  return 0;
}

/**
 * @brief A callback function that runs on single logical core in order
 *  to enable VMX.
 *
 * @param u Unused parameter (it's a callback after all)
 * @return __init enable_vmx  Status code
 */
__init int enable_vmx(void *u) {
  unsigned long old_fc, test_bits;
  vmcs_t *vmx_area = __this_cpu_read(vmxarea);

  rdmsrl(MSR_IA32_FEATURE_CONTROL, old_fc);

  test_bits = FEATURE_CONTROL_LOCKED;
  test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

  if (tboot_enabled())
    test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

  if ((old_fc & test_bits) != test_bits) {
    /* enable and lock */
    wrmsrl(MSR_IA32_FEATURE_CONTROL, old_fc | test_bits);
  }

  cr4_set_bits(X86_CR4_VMXE);

  __vmxon(__pa(vmx_area));
  return 0;
}

static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
                                                  unsigned int order) {
  return alloc_pages_node(nid, gfp_mask, order);
}

vmcs_t *__vmx_alloc_vmcs(int cpu) {

  int node = cpu_to_node(cpu);
  struct page *pages;
  vmcs_t *_vmcs;

  pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);
  if (!pages)
    return NULL;
  _vmcs = page_address(pages);
  memset(_vmcs, 0, vmcs_config.size);
  _vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
  return _vmcs;
}

inline void __vmxon(u64 addr) {
  asm volatile(ASM_VMX_VMXON_RAX : : "a"(&addr), "m"(addr) : "memory", "cc");
}

__init int setup_vmcs_config(vmcs_config_t *vmcs_conf) {
  u32 vmx_msr_low, vmx_msr_high;
  u32 min, opt, min2, opt2;
  u32 _pin_based_exec_control = 0;
  u32 _cpu_based_exec_control = 0;
  u32 _cpu_based_2nd_exec_control = 0;
  u32 _vmexit_control = 0;
  u32 _vmentry_control = 0;

  min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
  opt = PIN_BASED_VIRTUAL_NMIS;
  if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
                          &_pin_based_exec_control) < 0)
    return -EIO;

  min =
#ifdef CONFIG_X86_64
      CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING |
#endif
      CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
      CPU_BASED_MOV_DR_EXITING | CPU_BASED_USE_TSC_OFFSETING |
      CPU_BASED_INVLPG_EXITING;

  opt = CPU_BASED_TPR_SHADOW | CPU_BASED_USE_MSR_BITMAPS |
        CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
  if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
                          &_cpu_based_exec_control) < 0)
    return -EIO;
#ifdef CONFIG_X86_64
  if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
    _cpu_based_exec_control &=
        ~CPU_BASED_CR8_LOAD_EXITING & ~CPU_BASED_CR8_STORE_EXITING;
#endif
  if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
    min2 = 0;
    opt2 = SECONDARY_EXEC_WBINVD_EXITING | SECONDARY_EXEC_ENABLE_VPID |
           SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_RDTSCP |
           SECONDARY_EXEC_ENABLE_INVPCID;
    if (adjust_vmx_controls(min2, opt2, MSR_IA32_VMX_PROCBASED_CTLS2,
                            &_cpu_based_2nd_exec_control) < 0)
      return -EIO;
  }
#ifndef CONFIG_X86_64
  if (!(_cpu_based_2nd_exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
    _cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
  if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
    /* CR3 accesses and invlpg don't need to cause VM Exits when EPT
       enabled */
    _cpu_based_exec_control &=
        ~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |
          CPU_BASED_INVLPG_EXITING);
    rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, _vmx_capability.ept, _vmx_capability.vpid);
  }

  min = 0;
#ifdef CONFIG_X86_64
  min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
  //	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
  opt = 0;
  if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS, &_vmexit_control) <
      0)
    return -EIO;

  min = 0;
  //	opt = VM_ENTRY_LOAD_IA32_PAT;
  opt = 0;
  if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
                          &_vmentry_control) < 0)
    return -EIO;

  rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

  /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
  if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
    return -EIO;

#ifdef CONFIG_X86_64
  /* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
  if (vmx_msr_high & (1u << 16))
    return -EIO;
#endif

  /* Require Write-Back (WB) memory type for VMCS accesses. */
  if (((vmx_msr_high >> 18) & 15) != 6)
    return -EIO;

  vmcs_conf->size = vmx_msr_high & 0x1fff;
  vmcs_conf->order = get_order(vmcs_config.size);
  vmcs_conf->revision_id = vmx_msr_low;

  vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
  vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
  vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
  vmcs_conf->vmexit_ctrl = _vmexit_control;
  vmcs_conf->vmentry_ctrl = _vmentry_control;

  _vmx_capability.has_load_efer =
      allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS, VM_ENTRY_LOAD_IA32_EFER) &&
      allow_1_setting(MSR_IA32_VMX_EXIT_CTLS, VM_EXIT_LOAD_IA32_EFER);

  return 0;
}

int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt, u32 msr, u32 *result) {
  u32 vmx_msr_low, vmx_msr_high;
  u32 ctl = ctl_min | ctl_opt;

  rdmsr(msr, vmx_msr_low, vmx_msr_high);

  ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
  ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

  /* Ensure minimum (required) set of control bits are supported. */
  if (ctl_min & ~ctl)
    return -EIO;

  *result = ctl;
  return 0;
}

__init bool allow_1_setting(u32 msr, u32 ctl) {
  u32 vmx_msr_low, vmx_msr_high;

  rdmsr(msr, vmx_msr_low, vmx_msr_high);
  return vmx_msr_high & ctl;
}

inline bool cpu_has_vmx_vpid(void) {
  return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_VPID;
}

inline bool cpu_has_vmx_ept(void) {
  return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_EPT;
}
