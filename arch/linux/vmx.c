#include "vmx.h"

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_PER_CPU(vmcs_t *, vmxarea);
DEFINE_PER_CPU(vmx_vcpu_t *, local_vcpu);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);
static DEFINE_SPINLOCK(vmx_vpid_lock);
static LIST_HEAD(vcpus);

static vmcs_config_t vmcs_config;
vmx_capability_t vmx_capability;

static inline bool cpu_has_vmx_ept(void) {
  return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_EPT;
}

static inline bool cpu_has_vmx_vpid(void) {
  return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_invvpid_global(void) {
  return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa) {
  struct {
    u64 eptp, gpa;
  } operand = {eptp, gpa};

  asm volatile(ASM_VMX_INVEPT
               /* CF==1 or ZF==1 --> rc = -1 */
               "; ja 1f ; ud2 ; 1:\n"
               :
               : "a"(&operand), "c"(ext)
               : "cc", "memory");
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva) {
  struct {
    u64 vpid : 16;
    u64 rsvd : 48;
    u64 gva;
  } operand = {vpid, 0, gva};

  asm volatile(ASM_VMX_INVVPID
               /* CF==1 or ZF==1 --> rc = -1 */
               "; ja 1f ; ud2 ; 1:"
               :
               : "a"(&operand), "c"(ext)
               : "cc", "memory");
}

static inline void vpid_sync_vcpu_global(void) {
  if (cpu_has_vmx_invvpid_global())
    __invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline bool cpu_has_vmx_invept_global(void) {
  return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline void ept_sync_global(void) {
  if (cpu_has_vmx_invept_global())
    __invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static void vmcs_clear(vmcs_t *vmcs) {
  u64 phys_addr = __pa(vmcs);
  u8 error;

  asm volatile(ASM_VMX_VMCLEAR_RAX "; setna %0"
               : "=qm"(error)
               : "a"(&phys_addr), "m"(phys_addr)
               : "cc", "memory");
  if (error)
    printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n", vmcs, phys_addr);
}

static void __vmx_get_cpu_helper(void *ptr) {
  vmx_vcpu_t *vcpu = (vmx_vcpu_t *)ptr;

  BUG_ON(raw_smp_processor_id() != vcpu->cpu);
  vmcs_clear(vcpu->vmcs);
  if (__this_cpu_read(local_vcpu) == vcpu)
    this_cpu_write(local_vcpu, NULL);
}

static inline bool cpu_has_vmx_invvpid_single(void) {
  return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline void vpid_sync_vcpu_single(u16 vpid) {
  if (vpid == 0)
    return;

  if (cpu_has_vmx_invvpid_single())
    __invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
}

static inline void vpid_sync_context(u16 vpid) {
  if (cpu_has_vmx_invvpid_single())
    vpid_sync_vcpu_single(vpid);
  else
    vpid_sync_vcpu_global();
}

static inline bool cpu_has_vmx_invept_context(void) {
  return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline void ept_sync_context(u64 eptp) {
  if (cpu_has_vmx_invept_context())
    __invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
  else
    ept_sync_global();
}

static void vmcs_load(vmcs_t *vmcs) {
  u64 phys_addr = __pa(vmcs);
  u8 error;

  asm volatile(ASM_VMX_VMPTRLD_RAX "; setna %0"
               : "=qm"(error)
               : "a"(&phys_addr), "m"(phys_addr)
               : "cc", "memory");
  if (error)
    printk(KERN_ERR "vmx: vmptrld %p/%llx failed\n", vmcs, phys_addr);
}

static inline bool cpu_has_vmx_ept_ad_bits(void) {
  return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static __always_inline unsigned long vmcs_readl(unsigned long field) {
  unsigned long value;

  asm volatile(ASM_VMX_VMREAD_RDX_RAX : "=a"(value) : "d"(field) : "cc");
  return value;
}

static __always_inline u16 vmcs_read16(unsigned long field) {
  return vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field) {
  return vmcs_readl(field);
}

static noinline void vmwrite_error(unsigned long field, unsigned long value) {
  printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n", field, value,
         vmcs_read32(VM_INSTRUCTION_ERROR));
  dump_stack();
}

static void vmcs_writel(unsigned long field, unsigned long value) {
  u8 error;

  asm volatile(ASM_VMX_VMWRITE_RAX_RDX "; setna %0"
               : "=q"(error)
               : "a"(value), "d"(field)
               : "cc");
  if (unlikely(error))
    vmwrite_error(field, value);
}

static void vmcs_write32(unsigned long field, u32 value) {
  vmcs_writel(field, value);
}

static inline u16 vmx_read_ldt(void) {
  u16 ldt;
  asm("sldt %0" : "=g"(ldt));
  return ldt;
}

static unsigned long segment_base(u16 selector) {
  struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
  struct desc_struct *d;
  unsigned long table_base;
  unsigned long v;

  if (!(selector & ~3))
    return 0;

  table_base = gdt->address;

  if (selector & 4) { /* from ldt */
    u16 ldt_selector = vmx_read_ldt();

    if (!(ldt_selector & ~3))
      return 0;

    table_base = segment_base(ldt_selector);
  }
  d = (struct desc_struct *)(table_base + (selector & ~7));
  v = get_desc_base(d);
#ifdef CONFIG_X86_64
  if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
    v |= (unsigned long)((ldt_desc *)d)->base3 << 32;
#endif
  return v;
}

static inline unsigned long vmx_read_tr_base(void) {
  u16 tr;
  asm("str %0" : "=g"(tr));
  return segment_base(tr);
}

static void __vmx_setup_cpu(void) {
  struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
  unsigned long sysenter_esp;
  unsigned long tmpl;

  /*
   * Linux uses per-cpu TSS and GDT, so set these when switching
   * processors.
   */
  vmcs_writel(HOST_TR_BASE, vmx_read_tr_base()); /* 22.2.4 */
  vmcs_writel(HOST_GDTR_BASE, gdt->address);     /* 22.2.4 */

  rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
  vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

  rdmsrl(MSR_FS_BASE, tmpl);
  vmcs_writel(HOST_FS_BASE, tmpl); /* 22.2.4 */
  rdmsrl(MSR_GS_BASE, tmpl);
  vmcs_writel(HOST_GS_BASE, tmpl); /* 22.2.4 */
}

static void vmx_get_cpu(vmx_vcpu_t *vcpu) {
  int cur_cpu = get_cpu();

  if ((vmx_vcpu_t *)__this_cpu_read(local_vcpu) != vcpu) {
    this_cpu_write(local_vcpu, vcpu);

    if (vcpu->cpu != cur_cpu) {
      if (vcpu->cpu >= 0)
        smp_call_function_single(vcpu->cpu, __vmx_get_cpu_helper, (void *)vcpu,
                                 1);
      else
        vmcs_clear(vcpu->vmcs);

      vpid_sync_context(vcpu->vpid);
      ept_sync_context(vcpu->eptp);

      vcpu->launched = 0;
      vmcs_load(vcpu->vmcs);
      __vmx_setup_cpu();
      vcpu->cpu = cur_cpu;
    } else {
      vmcs_load(vcpu->vmcs);
    }
  }
}

static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
                                                  unsigned int order) {
  return alloc_pages_node(nid, gfp_mask, order);
}

vmcs_t *__vmx_alloc_vmcs(u32 cpu) {
  int node = cpu_to_node(cpu);
  struct page *pages;
  vmcs_t *vmcs;

  pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);

  if (!pages)
    return NULL;

  vmcs = (vmcs_t *)page_address(pages);
  memset(vmcs, 0, vmcs_config.size);
  vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
  return vmcs;
}

static int vmx_allocate_vpid(vmx_vcpu_t *vmx) {
  u32 vpid;

  vmx->vpid = 0;

  spin_lock(&vmx_vpid_lock);
  vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);

  if (vpid < VMX_NR_VPIDS) {
    vmx->vpid = vpid;
    __set_bit(vpid, vmx_vpid_bitmap);
  }
  spin_unlock(&vmx_vpid_lock);

  return vpid >= VMX_NR_VPIDS;
}

static vmcs_t *vmx_alloc_vmcs(void) {
  return __vmx_alloc_vmcs(raw_smp_processor_id());
}

static inline bool cpu_has_secondary_exec_ctrls(void) {
  return vmcs_config.cpu_based_exec_ctrl &
         CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}
static inline bool cpu_has_vmx_invpcid(void) {
  return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_INVPCID;
}

static __always_inline u64 vmcs_read64(unsigned long field) {
#ifdef CONFIG_X86_64
  return vmcs_readl(field);
#else
  return vmcs_readl(field) | ((u64)vmcs_readl(field + 1) << 32);
#endif
}

static inline void ept_sync_individual_addr(u64 eptp, gpa_t gpa) {
  ept_sync_context(eptp);
}

static void vmx_put_cpu(vmx_vcpu_t *vcpu) { put_cpu(); }

static void vmx_setup_registers(vmx_vcpu_t *vcpu, vmx_state_t *conf) {
  vcpu->regs[VCPU_REGS_RAX] = conf->rax;
  vcpu->regs[VCPU_REGS_RBX] = conf->rbx;
  vcpu->regs[VCPU_REGS_RCX] = conf->rcx;
  vcpu->regs[VCPU_REGS_RDX] = conf->rdx;
  vcpu->regs[VCPU_REGS_RSI] = conf->rsi;
  vcpu->regs[VCPU_REGS_RDI] = conf->rdi;
  vcpu->regs[VCPU_REGS_RBP] = conf->rbp;
  vcpu->regs[VCPU_REGS_R8] = conf->r8;
  vcpu->regs[VCPU_REGS_R9] = conf->r9;
  vcpu->regs[VCPU_REGS_R10] = conf->r10;
  vcpu->regs[VCPU_REGS_R11] = conf->r11;
  vcpu->regs[VCPU_REGS_R12] = conf->r12;
  vcpu->regs[VCPU_REGS_R13] = conf->r13;
  vcpu->regs[VCPU_REGS_R14] = conf->r14;
  vcpu->regs[VCPU_REGS_R15] = conf->r15;

  vmcs_writel(GUEST_RIP, conf->rip);
  vmcs_writel(GUEST_RSP, conf->rsp);
  vmcs_writel(GUEST_RFLAGS, conf->rflags);
}

static void vmx_copy_registers_to_conf(vmx_vcpu_t *vcpu, vmx_state_t *conf) {
  conf->rax = vcpu->regs[VCPU_REGS_RAX];
  conf->rbx = vcpu->regs[VCPU_REGS_RBX];
  conf->rcx = vcpu->regs[VCPU_REGS_RCX];
  conf->rdx = vcpu->regs[VCPU_REGS_RDX];
  conf->rsi = vcpu->regs[VCPU_REGS_RSI];
  conf->rdi = vcpu->regs[VCPU_REGS_RDI];
  conf->rbp = vcpu->regs[VCPU_REGS_RBP];
  conf->r8 = vcpu->regs[VCPU_REGS_R8];
  conf->r9 = vcpu->regs[VCPU_REGS_R9];
  conf->r10 = vcpu->regs[VCPU_REGS_R10];
  conf->r11 = vcpu->regs[VCPU_REGS_R11];
  conf->r12 = vcpu->regs[VCPU_REGS_R12];
  conf->r13 = vcpu->regs[VCPU_REGS_R13];
  conf->r14 = vcpu->regs[VCPU_REGS_R14];
  conf->r15 = vcpu->regs[VCPU_REGS_R15];
  conf->rip = vmcs_readl(GUEST_RIP);
  conf->rsp = vmcs_readl(GUEST_RSP);
  conf->rflags = vmcs_readl(GUEST_RFLAGS);
}

static void setup_perf_msrs(vmx_vcpu_t *vcpu) {
  int nr_msrs, i;
  struct perf_guest_switch_msr *msrs;
  struct vmx_msr_entry *e;

  msrs = perf_guest_get_msrs(&nr_msrs);

  vcpu->msr_autoload.nr = nr_msrs;

  vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vcpu->msr_autoload.nr);
  vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vcpu->msr_autoload.nr);

  for (i = 0; i < nr_msrs; i++) {
    e = &vcpu->msr_autoload.host[i];
    e->index = msrs[i].msr;
    e->value = msrs[i].host;
    e = &vcpu->msr_autoload.guest[i];
    e->index = msrs[i].msr;
    e->value = msrs[i].guest;
  }
}

static int __noclone vmx_run_vcpu(vmx_vcpu_t *vcpu) {
  asm(
      /* Store host registers */
      "push %%"R"dx; push %%"R"bp;" "push %%"R"cx \n\t" /* placeholder for guest
                                                           rcx */
      "push %%"R"cx \n\t" "cmp %%"R"sp, %c[host_rsp](%0) \n\t" "je 1f \n\t"
                                                               "mov "
                                                               "%"
                                                               "%"R"sp, %c[host_rsp](%0) \n\t" ASM_VMX_VMWRITE_RSP_RDX
      "\n\t"
      "1: \n\t"
      /* Reload cr2 if changed */
      "mov %c[cr2](%0), %%"R"ax \n\t" "mov %%cr2, %%"R"dx \n\t" "cmp "
                                                                "%"
                                                                "%"R"ax, %%"R"dx \n\t" "je 2f \n\t"
                                                                                       "mov %%"R"ax, %%cr2 \n\t" "2: \n\t"
                                                                                                                 /* Check if vmlaunch of vmresume is needed */
                                                                                                                 "cmpl $0, %c[launched](%0) \n\t"
                                                                                                                 /* Load guest registers.  Don't clobber flags. */
                                                                                                                 "mov %c[rax](%0), %%"R"ax \n\t" "mov %c[rbx](%0), %%"R"bx \n\t" "mov %c[rdx](%0), %%"R"dx \n\t" "mov %c[rsi](%0), %%"R"si \n\t" "mov %c[rdi](%0), %%"R"di \n\t" "mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
      "mov %c[r8](%0),  %%r8  \n\t"
      "mov %c[r9](%0),  %%r9  \n\t"
      "mov %c[r10](%0), %%r10 \n\t"
      "mov %c[r11](%0), %%r11 \n\t"
      "mov %c[r12](%0), %%r12 \n\t"
      "mov %c[r13](%0), %%r13 \n\t"
      "mov %c[r14](%0), %%r14 \n\t"
      "mov %c[r15](%0), %%r15 \n\t"
#endif
      "mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */

      /* Enter guest mode */
      "jne .Llaunched \n\t" ASM_VMX_VMLAUNCH "\n\t"
      "jmp .Lkvm_vmx_return \n\t"
      ".Llaunched: " ASM_VMX_VMRESUME "\n\t"
      ".Lkvm_vmx_return: "
      /* Save guest registers, load host registers, keep flags */
      "mov %0, %c[wordsize](%%"R"sp) \n\t" "pop %0 \n\t"
                                           "mov %%"R"ax, %c[rax](%0) \n\t" "mov"
                                                                           " %"
                                                                           "%"R"bx, %c[rbx](%0) \n\t" "pop" Q
                                                                                                      " %c[rcx](%0) \n\t"
                                                                                                      "mov %%"R"dx, %c[rdx](%0) \n\t" "mov %%"R"si, %c[rsi](%0) \n\t" "mov %%"R"di, %c[rdi](%0) \n\t" "mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
      "mov %%r8,  %c[r8](%0) \n\t"
      "mov %%r9,  %c[r9](%0) \n\t"
      "mov %%r10, %c[r10](%0) \n\t"
      "mov %%r11, %c[r11](%0) \n\t"
      "mov %%r12, %c[r12](%0) \n\t"
      "mov %%r13, %c[r13](%0) \n\t"
      "mov %%r14, %c[r14](%0) \n\t"
      "mov %%r15, %c[r15](%0) \n\t"
#endif
      "mov %%rax, %%r10 \n\t"
      "mov %%rdx, %%r11 \n\t"

      "mov %%cr2, %%"R"ax   \n\t" "mov %%"R"ax, %c[cr2](%0) \n\t"

      "pop  %%"R"bp; pop  %%"R"dx \n\t" "setbe %c[fail](%0) \n\t"

                                        "mov $" __stringify(
                                            __USER_DS) ", %%rax \n\t"
                                                       "mov %%rax, %%ds \n\t"
                                                       "mov %%rax, %%es \n\t"
      :
      : "c"(vcpu), "d"((unsigned long)HOST_RSP),
        [launched] "i"(offsetof(vmx_vcpu_t, launched)),
        [fail] "i"(offsetof(vmx_vcpu_t, fail)),
        [host_rsp] "i"(offsetof(vmx_vcpu_t, host_rsp)),
        [rax] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RAX])),
        [rbx] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RBX])),
        [rcx] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RCX])),
        [rdx] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RDX])),
        [rsi] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RSI])),
        [rdi] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RDI])),
        [rbp] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
        [r8] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R8])),
        [r9] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R9])),
        [r10] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R10])),
        [r11] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R11])),
        [r12] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R12])),
        [r13] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R13])),
        [r14] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R14])),
        [r15] "i"(offsetof(vmx_vcpu_t, regs[VCPU_REGS_R15])),
#endif
        [cr2] "i"(offsetof(vmx_vcpu_t, cr2)), [wordsize] "i"(sizeof(ulong))
      : "cc", "memory", R"ax", R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
        ,
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
  );

  vcpu->launched = 1;

  if (unlikely(vcpu->fail)) {
    printk(KERN_ERR "vmx: failure detected (err %x)\n",
           vmcs_read32(VM_INSTRUCTION_ERROR));
    return VMX_EXIT_REASONS_FAILED_VMENTRY;
  }

  return vmcs_read32(VM_EXIT_REASON);

#if 0
	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	vmx_complete_atomic_exit(vmx);
	vmx_recover_nmi_blocking(vmx);
	vmx_complete_interrupts(vmx);
#endif
}

static void inject_interrupt(int vector) {
#define CASE(i)                                                                \
  case i:                                                                      \
    asm("int $" #i);                                                           \
    break;
#define CASE8(i)                                                               \
  CASE(i + 0)                                                                  \
  CASE(i + 1) CASE(i + 2) CASE(i + 3) CASE(i + 4) CASE(i + 5) CASE(i + 6)      \
      CASE(i + 7)
#define CASE32(i) CASE8(i + 0) CASE8(i + 8) CASE8(i + 16) CASE8(i + 24)

  switch (vector) {
    CASE32(32)
    CASE32(64)
    CASE32(96)
    CASE32(128)
    CASE32(160)
    CASE32(192)
    CASE32(224)

  default:
    printk(KERN_WARNING "vmx: won't inject interrupt %d\n", vector);
    break;
  }

#undef CASE
#undef CASE8
#undef CASE32
}

static void vmx_handle_interrupts(int ret, vmx_vcpu_t *vcpu) {
  int i, j;
  u32 v;

  for (i = 7; i >= 0; i--) {
    v = apic_read(APIC_ISR + i * 16);
    if (!v)
      continue;

    for (j = 31; j >= 0; j--)
      if (v & (1 << j))
        inject_interrupt(i * 32 + j);
  }
}

static void vmx_step_instruction(void) {
  vmcs_writel(GUEST_RIP,
              vmcs_readl(GUEST_RIP) + vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
}

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
  if (!vmx_capability.has_load_efer) {
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

  if (__read_cr4() & X86_CR4_VMXE)
    return -EBUSY;

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
  vpid_sync_vcpu_global();
  ept_sync_global();

  return 0;
}

int vmx_launch(vmx_state_t *conf, int64_t *ret_code) {
  int ret, done = 0;
  u32 exit_intr_info;
  vmx_vcpu_t *vcpu = vmx_create_vcpu(conf);
  if (!vcpu)
    return -ENOMEM;

  glog(KERN_INFO, "vmx: created VCPU (VPID %d)\n");

  while (1) {
    vmx_get_cpu(vcpu);

    local_irq_disable();

    if (need_resched()) {
      local_irq_enable();
      vmx_put_cpu(vcpu);
      cond_resched();
      continue;
    }

    if (signal_pending(current)) {

      local_irq_enable();
      vmx_put_cpu(vcpu);

      vcpu->ret_code = DUNE_RET_SIGNAL;
      break;
    }

    setup_perf_msrs(vcpu);

    ret = vmx_run_vcpu(vcpu);

    /* We need to handle NMIs before interrupts are enabled */
    exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
    if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
        (exit_intr_info & INTR_INFO_VALID_MASK)) {
      asm("int $2");
    }

    vmx_handle_interrupts(ret, vcpu);

    local_irq_enable();

    if (ret == EXIT_REASON_VMCALL || ret == EXIT_REASON_CPUID) {
      vmx_step_instruction();
    }

    vmx_put_cpu(vcpu);

    if (done || vcpu->shutdown)
      break;
  }

  printk(KERN_ERR "vmx: stopping VCPU (VPID %d)\n", vcpu->vpid);

  *ret_code = vcpu->ret_code;

  vmx_copy_registers_to_conf(vcpu, conf);

  return 0;
}

vmx_vcpu_t *vmx_create_vcpu(vmx_state_t *state) {
  vmx_vcpu_t *vcpu = NULL;

  if (state->vcpu) {
    vcpu = (vmx_vcpu_t *)state->vcpu;
    vmx_get_cpu(vcpu);
    vmx_setup_registers(vcpu, state);
    vmx_put_cpu(vcpu);

    return vcpu;
  }

  vcpu = (vmx_vcpu_t *)kmalloc(sizeof(vmx_vcpu_t), GFP_KERNEL);

  if (!vcpu) {
    return NULL;
  }

  memset(vcpu, 0, sizeof(vmx_vcpu_t));
  list_add(&vcpu->list, &vcpus);

  vcpu->state = state;
  state->vcpu = (u64)vcpu;

  vcpu->vmcs = vmx_alloc_vmcs();

  /* TODO: validations */

  return NULL;
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
    rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_capability.ept, vmx_capability.vpid);
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

  vmx_capability.has_load_efer =
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
