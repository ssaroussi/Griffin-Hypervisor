#include <asm/paravirt.h>
#include <asm/virtext.h>
#include <linux/cpumask.h>
#include <linux/module.h>

#include "util.h"

__init int enable_vmx(void *shit);
int init_vmx(void);