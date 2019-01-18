#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/paravirt.h>
#include <asm/virtext.h>
#include <linux/cpumask.h>
#include <linux/gfp.h>
#include <linux/kvm_types.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/tboot.h>

#include "util.h"

enum vmx_reg {
  VCPU_REGS_RAX = 0,
  VCPU_REGS_RCX = 1,
  VCPU_REGS_RDX = 2,
  VCPU_REGS_RBX = 3,
  VCPU_REGS_RSP = 4,
  VCPU_REGS_RBP = 5,
  VCPU_REGS_RSI = 6,
  VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
  VCPU_REGS_R8 = 8,
  VCPU_REGS_R9 = 9,
  VCPU_REGS_R10 = 10,
  VCPU_REGS_R11 = 11,
  VCPU_REGS_R12 = 12,
  VCPU_REGS_R13 = 13,
  VCPU_REGS_R14 = 14,
  VCPU_REGS_R15 = 15,
#endif
  VCPU_REGS_RIP,
  NR_VCPU_REGS
};

#define NR_AUTOLOAD_MSRS 8

typedef struct VMX_STATE {
  __s64 ret;
  __u64 rax;
  __u64 rbx;
  __u64 rcx;
  __u64 rdx;
  __u64 rsi;
  __u64 rdi;
  __u64 rsp;
  __u64 rbp;
  __u64 r8;
  __u64 r9;
  __u64 r10;
  __u64 r11;
  __u64 r12;
  __u64 r13;
  __u64 r14;
  __u64 r15;
  __u64 rip;
  __u64 rflags;
  __u64 cr3;
  __s64 status;
  __u64 vcpu;
} __attribute__((packed)) vmx_state_t;

typedef struct VMCS_CONFIG {
  int size;
  int order;
  u32 revision_id;
  u32 pin_based_exec_ctrl;
  u32 cpu_based_exec_ctrl;
  u32 cpu_based_2nd_exec_ctrl;
  u32 vmexit_ctrl;
  u32 vmentry_ctrl;
} vmcs_config_t;

typedef struct VMCS {
  u32 revision_id;
  u32 abort;
  char data[0];
} vmcs_t;

typedef struct VMC_CAPABILITY {
  u32 ept;
  u32 vpid;
  int has_load_efer : 1;
} vmx_capability_t;

typedef struct VMX_VCPU {
  struct list_head list;
  int cpu;
  int vpid;
  int launched;

  struct mmu_notifier mmu_notifier;
  spinlock_t ept_lock;
  unsigned long ept_root;
  unsigned long eptp;
  bool ept_ad_enabled;

  u8 fail;
  u64 exit_reason;
  u64 host_rsp;
  u64 regs[NR_VCPU_REGS];
  u64 cr2;

  int shutdown;
  int ret_code;

  struct msr_autoload {
    unsigned nr;
    struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
    struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
  } msr_autoload;

  vmcs_t *vmcs;
  void *syscall_tbl;
  vmx_state_t *state;
} vmx_vcpu_t;

__init int enable_vmx(void *u);
__init int init_vmx(void);
__init int setup_vmcs_config(vmcs_config_t *vmcs_conf);
__init bool allow_1_setting(u32 msr, u32 ctl);

inline void __vmxon(u64 addr);

extern vmx_capability_t vmx_capability;

vmcs_t *__vmx_alloc_vmcs(u32 cpu);
int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt, u32 msr, u32 *result);