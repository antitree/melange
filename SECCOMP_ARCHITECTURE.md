# Melange Seccomp Monitoring Architecture

## Overview

This document describes the seccomp-based syscall monitoring system integrated into melange for build provenance and security analysis.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Melange       │───▶│   Seccomp-BPF    │───▶│   Kernel        │
│   Process       │    │   Profile        │    │   Logging       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ CLI Parameter   │    │ SCMP_ACT_ALLOW   │    │    syslog       │
│ --seccomp-mode  │    │ SCMP_ACT_LOG     │    │   messages      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Syscall Categories

### High-Risk Syscalls (SCMP_ACT_LOG)
These syscalls are allowed but logged for security analysis:

**Process Control & Execution:**
- `execve`, `execveat` - Process execution
- `clone`, `fork`, `vfork` - Process creation
- `ptrace` - Process debugging/tracing
- `setuid`, `setgid`, `setreuid`, `setregid` - Privilege changes
- `setresuid`, `setresgid` - Extended privilege changes
- `capset`, `capget` - Capability manipulation

**File System & Security:**
- `mount`, `umount`, `umount2` - Filesystem mounting
- `chroot` - Root directory changes
- `pivot_root` - Root pivot operations
- `swapon`, `swapoff` - Swap management
- `quotactl` - Quota management
- `sysfs` - sysfs operations
- `unshare` - Namespace operations
- `setns` - Namespace joining

**Network Operations:**
- `socket` - Socket creation
- `bind` - Socket binding
- `connect` - Network connections
- `listen`, `accept`, `accept4` - Server operations
- `sendmsg`, `recvmsg` - Advanced network I/O
- `sendmmsg`, `recvmmsg` - Batch network operations

**System Configuration:**
- `init_module`, `finit_module` - Kernel module loading
- `delete_module` - Kernel module removal
- `reboot` - System reboot
- `settimeofday` - Time modification
- `adjtimex` - Time adjustment
- `clock_settime` - Clock setting

### Low-Risk Syscalls (SCMP_ACT_ALLOW)
These syscalls are allowed without logging:

**File I/O (Basic):**
- `read`, `write`, `pread64`, `pwrite64`
- `readv`, `writev`, `preadv`, `pwritev`
- `open`, `openat`, `creat`
- `close`, `dup`, `dup2`, `dup3`
- `lseek`, `llseek`
- `stat`, `fstat`, `lstat`, `newfstatat`
- `access`, `faccessat`

**Memory Management:**
- `mmap`, `munmap`, `mprotect`, `madvise`
- `brk`, `sbrk`, `mremap`
- `mlock`, `munlock`, `mlockall`, `munlockall`

**Directory Operations:**
- `getcwd`, `chdir`, `fchdir`
- `mkdir`, `mkdirat`, `rmdir`
- `readdir`, `getdents`, `getdents64`

**Process Information:**
- `getpid`, `getppid`, `gettid`
- `getuid`, `geteuid`, `getgid`, `getegid`
- `getgroups`, `getresuid`, `getresgid`

**Time & Signals:**
- `time`, `gettimeofday`, `clock_gettime`
- `nanosleep`, `clock_nanosleep`
- `alarm`, `setitimer`, `getitimer`
- `signal`, `sigaction`, `sigprocmask`
- `sigreturn`, `rt_sigreturn`

**Polling & I/O Control:**
- `select`, `pselect6`, `poll`, `ppoll`
- `epoll_create`, `epoll_ctl`, `epoll_wait`
- `ioctl`, `fcntl`

## Implementation Details

### CLI Integration
- New flag: `--seccomp-mode` (optional)
- When enabled, applies seccomp profile before build execution
- Only supported on AMD64 architecture

### Logging Format
```
[SECCOMP] pid=1234 comm=gcc syscall=execve(59) args=["/usr/bin/ld", "-o", "output"]
```

### Error Handling
- If seccomp fails to load, melange exits with error
- Clear error messages for unsupported architectures
- Graceful fallback if kernel doesn't support seccomp

### Testing Strategy
1. **Unit Tests**: Verify seccomp policy construction
2. **Integration Tests**: Test syscall logging with known syscalls
3. **Coverage Tests**: Ensure no bypass possibilities
4. **Architecture Tests**: Verify AMD64-only restriction

## Configuration Options

```go
type SeccompConfig struct {
    Enabled          bool              `yaml:"enabled" json:"enabled"`
    LogDangerous     bool              `yaml:"log_dangerous" json:"log_dangerous"`
    AllowList        []string          `yaml:"allow_list" json:"allow_list"`
    LogList          []string          `yaml:"log_list" json:"log_list"`
    FailOnViolation  bool              `yaml:"fail_on_violation" json:"fail_on_violation"`
}
```

## Security Considerations

### Bypass Prevention
- Profile applied early in process startup
- No runtime disable mechanism
- Comprehensive syscall coverage
- Architecture validation

### Performance Impact
- Minimal overhead for allowed syscalls
- Logging overhead only for dangerous syscalls
- Expected <1% performance impact during builds

### Audit Trail
- All dangerous syscalls logged with context
- Process hierarchy information included
- Timestamp and argument capture
- Integration with existing melange logging