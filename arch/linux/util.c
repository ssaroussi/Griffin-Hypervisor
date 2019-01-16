#include "util.h"

/**
 * @brief Prints a custom message to the kernel log buffer.
 *
 * @param type One of the message types (KERN_ERR, KERN_INFO, etc)
 * @param msg The message
 */
void glog(const char *type, const char *msg) {
  printk("%sgriffin: %s\n", type, msg);
}
