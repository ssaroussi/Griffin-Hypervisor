#include <linux/module.h>

#include "util.h"
#include "vmx.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amit Saroussi & Lior Fainbrun");
MODULE_DESCRIPTION("A dynamic loader for the Griffin Hypervisor");
MODULE_VERSION("0.1");

static __init int gvj_init(void) {
  glog(KERN_INFO, "Griffin - In");

  if (init_vmx()) {
    glog(KERN_ERR, "Exiting");
    return -EIO;
  }

  glog(KERN_INFO, "Griffin succesfully loaded");
  return 0;
}

static void gvj_exit(void) { glog(KERN_INFO, "Griffin - Out"); }

module_init(gvj_init);
module_exit(gvj_exit);
