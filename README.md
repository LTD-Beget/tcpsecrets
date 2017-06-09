# tcpsecrets
Linux kernel module to provide access to tcp cookie secrets via /proc/tcp_secrets

## Tested kernels
- 4.2.0-35-generic #40~14.04.1-Ubuntu 
- 4.4.0-34-generic #53~14.04.1-Ubuntu 
- 4.6.0-0.bpo.1-amd64 #1 SMP Debian 4.6.4-1~bpo8+1
- 4.9.0-0.bpo.3-amd64 #1 SMP Debian 4.9.25-1~bpo8+1

## Untested kernels
- 3.16.0-4-amd64 #1 SMP Debian 3.16.36-1+deb8u1 (builds, not tested)

## Unsupported kernels
- 2.6.x 

## Custom kernels
These options are required for module to work:

```
CONFIG_LIVEPATCH=y
CONFIG_FTRACE=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_FTRACE_MCOUNT_RECORD=y
```

## Install via DKMS

    KERNEL_VERSION=$(uname -r) make -f Makefile.dkms
