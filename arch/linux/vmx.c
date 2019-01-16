#include "vmx.h"

/**
 * @brief Enables VMX on every logical core with an appropriate
 *  configuration.
 *
 * @return __init init_vmx Status code.
 */
__init int init_vmx(void) {
  unsigned long old_fc, test_bits;

  /* Ensure the CPU supports VT-x */
  if (!cpu_has_vmx()) {
    glog(KERN_ERR, "CPU does not support VT-x");
    return -EIO;
  }

  rdmsrl(MSR_IA32_FEATURE_CONTROL, old_fc);

  test_bits = FEATURE_CONTROL_LOCKED;
  test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

  if (tboot_enabled())
    test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

  if ((old_fc & test_bits) != test_bits) {
    /* enable and lock */
    wrmsrl(MSR_IA32_FEATURE_CONTROL, old_fc | test_bits);
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
  cr4_set_bits(X86_CR4_VMXE);
  return 0;
}