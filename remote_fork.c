#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "pmparser.h"
#include "remote_fork.h"

/* ---------- Static functions declarations ---------- */

// static int _prot(Mapping* m);

static Result const fork_frozen();

/*Kill the child process if the parent dies.*/
static int const kill_if_parent_dies();

static bool const is_special_kernel_map(procmaps_struct* map);
static bool const forced_transfer_kernel_map(procmaps_struct* map);
static bool const should_skip_map(procmaps_struct* map);

static void write_special_kernel_map(FILE* out, procmaps_struct* map);
static void write_regular_map(FILE* out, pid_t child, procmaps_struct* map);
static void write_state(FILE* out, pid_t child, ProcessState proc_state);

static void single_step(pid_t child);

static size_t try_to_find_syscall(pid_t child, size_t addr);

static char* const get_map_name(procmaps_struct* map);

static off_t min(off_t a, off_t b);

/* ---------- Replicating Linux's memory mappings ---------- */

static size_t remote_brk(pid_t child, __uint64_t sysCall, size_t brk);
static size_t remote_mmap_anon(pid_t child, __uint64_t sysCall, size_t addr, size_t length, int32_t prot);
static void remote_munmap(pid_t child, __uint64_t sysCall, size_t addr, size_t length);
static void remote_mremap(pid_t child, __uint64_t sysCall, size_t addr, size_t length, size_t new_addr);
static void stream_memory(pid_t child, FILE* in, size_t addr, size_t length);

static procmaps_struct* find_map_named(procmaps_iterator* maps, char* name);

static void restore_brk(pid_t child, __uint64_t sysCall, size_t brk_addr);

/* ---------- Definitions ---------- */

// int _prot(Mapping* m) {
//   int prot = 0;
//   if (m->readable) {
//     prot |= PROT_READ;
//   }
//   if (m->writable) {
//     prot |= PROT_WRITE;
//   }
//   if (m->executable) {
//     prot |= PROT_EXEC;
//   }

//   return prot;
// }


Result const remote_fork(FILE* out) {
  ProcessState const proc_state = {.brk_address = (__uint64_t) sbrk(0)};
  Result const fork_meta = fork_frozen();

  if (fork_meta.loc == Child) {
	  printf("child in remote_fork returns\n");
	  return fork_meta;
  }

  // int status;
  //printf("current child (pid %d) status after fork_frozen: %d\n", fork_meta.pid, waitpid(fork_meta.pid, &status, WNOHANG));
  write_state(out, fork_meta.pid, proc_state);
  kill(fork_meta.pid, SIGKILL);
  // Only the parent retuns
  return fork_meta;
};

Result const fork_frozen() {
  pid_t pid = fork(); // fork() returns 0 to the child process and returns the process ID of the child process to the parent.
  if (pid == 0) {
    // This is the child process
    kill_if_parent_dies();
    // Allow the child to be traced by the parent.
    ptrace(PTRACE_TRACEME);
    // Stop the process for now. We will rehydrate from this point.
    int const raise_result = raise(SIGSTOP);

    printf("process rehydrated\n");
    Result const res = {.raise_result = raise_result, .loc = Child};

    return res;
  }
  // Parent process. The pid here is the child' pid, not the parent which is what we want.
  int status;
  waitpid(pid, &status, 0);

  Result res = {
	  .loc = Parent
  };

  if WIFSTOPPED(status) {
    res.pid = pid;
    return res;
  }
  
  raise_error("couldn't trace child");
  return res;
};

int const kill_if_parent_dies() {
  return prctl(PR_SET_PDEATHSIG, SIGKILL);
}

// Remapping these are just too difficult.
bool const is_special_kernel_map(procmaps_struct* map) {
  char* const file_name = get_map_name(map);
  if (strcmp(file_name, "[vdso]") != 0 && strcmp(file_name, "[vsyscall]") != 0 && strcmp(file_name, "[vvar]") != 0 )  {
	  return false;
  }
  return true;
}

bool const forced_transfer_kernel_map(procmaps_struct* map) {
  if (!FORCED_VDSO_TRANSFER) {
	return false;
  }

  char* const file_name = get_map_name(map);
  if (strcmp(file_name, "[vdso]") == 0) {
	  return true;
  }
  return false;
}

bool const should_skip_map(procmaps_struct* map) {
  if (!map->is_r || map->length == 0) {
	  return true;
  }
  return false;
}

void write_special_kernel_map(FILE* out, procmaps_struct* map) {
  char* const m_name = get_map_name(map);
  if (m_name == (void*)0) {
	  raise_error("a kernel map must have a name");
  }

  Remap const remap_cmd = {
    .addr = (size_t) map->addr_start, 
    .size = map->length
  };
  strcpy(remap_cmd.name, m_name);


  Command cmd = {
    .type = REMAP,
    .cmds = {
      .rm = remap_cmd,
    }
  };

  if (fwrite(&cmd, sizeof(Command), 1, out) == 0) {
	  raise_error("unable to write special kernel map");
  };
}

void write_regular_map(FILE* out, pid_t child, procmaps_struct* map) {
  char* const m_name = get_map_name(map);
  if (m_name == (void*)0) {
	  raise_error("a kernel map must have a name");
  }

  Mapping const mapping = {
    .readable = map->is_r,
    .writable = map->is_r,
    .executable = map->is_x,
    .addr = map->addr_start,
    .size = map->length,
  };
  strcpy(mapping.name, m_name);

  Command cmd = {
    .type = MAPPING,
    .cmds = {
      .mp = mapping,
    }
  };

  if (fwrite(&cmd, sizeof(Command), 1, out) == 0) {
	raise_error("unable to write regular map");
  }

  off_t remaining_size = map->length;
  char* buf = calloc(SYS_PAGE_SIZE, sizeof(char));
  while (remaining_size > 0) {
	off_t read_size = min(remaining_size, SYS_PAGE_SIZE);
	off_t offset = (off_t) map->addr_start + (map->length - remaining_size);

	struct iovec local[1];
	local[0].iov_base = buf;
	local[0].iov_len = read_size;
	
	struct iovec remote[1];
	remote[0].iov_base = (void*) offset;
	remote[0].iov_len = read_size;

	ssize_t wrote = process_vm_readv(child, local, 2, remote, 1, 0);
	if (wrote == 0) {
	  raise_error("failed to read from other process");
	}


	if (fwrite(buf, read_size, 1, out) != 1) {
	  if (ferror(out) != 0) {
		raise_error("failed writing regular map");
	  }
	}
	remaining_size -= read_size;
  }
  fflush(out);

  free(buf);
}

void write_state(FILE* out, pid_t child, ProcessState proc_state) {
  Command cmd = {
    .type = PROCESS_STATE,
    .cmds = {
      .ps = proc_state,
    }
  };

  if (fwrite(&cmd, sizeof(Command), 1, out) == 0) {
	  raise_error("error writing process state");
  }

  //printf("current child (pid %d) status after fork_frozen: %d\n", child, waitpid(child, (void*)0, WNOHANG));

  procmaps_iterator* maps = pmparser_parse(child);
  if (maps == (void*)0) {
	// printf("%d\n", child);
	  raise_error("error getting proc maps");
  }

  procmaps_struct* map_tmp = (void*)0;
  while ((map_tmp = pmparser_next(maps)) != (void*)0) {
    if (should_skip_map(map_tmp)) {
      continue;
    }

	  if (is_special_kernel_map(map_tmp) && !forced_transfer_kernel_map(map_tmp)) {
      write_special_kernel_map(out, map_tmp);
    } else {
      write_regular_map(out, child, map_tmp);
    }
  }
  
  fflush(out);
  // pmparser_free(maps);

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child, (void*)0, &regs);

  Command cmd_res = {
    .type = RESUME_WITH_REGISTERS,
    .cmds = {
      .rwr = {
        .user = regs,
      }
    }
  };

  if (fwrite(&cmd_res, sizeof(Command), 1, out) == 0) {
	  raise_error("error writing registers command");
  }
}

// void print_maps_info(procmaps_struct* map) {
//   pmparser_print(map, 0);
//   printf("\\n~~~~~~~~~~~~~~~~~~~~~~~~~\n");
// }

void single_step(pid_t child) {
  ptrace(PTRACE_SINGLESTEP, child);
  int status;
  waitpid(child, &status, 0);

  if (!WIFSTOPPED(status)) {
	  raise_error("couldn't trace child");
  }
}

size_t try_to_find_syscall(pid_t child, size_t addr) {
  char* buf = calloc(SYS_PAGE_SIZE, sizeof(char)); // 4096 bytes
  
  struct iovec local[1];
  local[0].iov_base = buf;
  local[0].iov_len = SYS_PAGE_SIZE;
  
  struct iovec remote[1];
  remote[0].iov_base = (void*) addr;
  remote[0].iov_len = SYS_PAGE_SIZE;

  ssize_t wrote = process_vm_readv(child, local, 2, remote, 1, 0);
  if (wrote == 0) {
	  raise_error("error writing from remote process");
  }

  __uint64_t syscalls[] = {0x0f, 0x05};
  for (size_t i = 0; i < SYS_PAGE_SIZE - 1; i ++) {
    if (buf[i] == syscalls[0] && buf[i+1] == syscalls[1]) {
      return i;
    }
  }

  free(buf);
  return raise_error("couldn't find syscall");
}

size_t remote_brk(pid_t child, __uint64_t sysCall, size_t brk) {
  /*Get the current state*/
  struct user_regs_struct syscall_regs;
  ptrace(PTRACE_GETREGS, child, 0, &syscall_regs);

  /*Modify it*/
  syscall_regs.rip = sysCall;
  syscall_regs.rax = 12;
  syscall_regs.rdi = brk;

  /*Set it*/
  ptrace(PTRACE_SETREGS, child, 0, &syscall_regs);
  /*Execute it*/
  single_step(child);
  /*Get the instructions to extract return value from rax*/
  struct user_regs_struct new_regs;
  ptrace(PTRACE_GETREGS, child, 0, &new_regs);

  return new_regs.rax;
}

size_t remote_mmap_anon(pid_t child, __uint64_t sysCall, size_t addr, size_t length, int32_t prot) {
  if (length % SYS_PAGE_SIZE != 0) {
	raise_error("mmap length must be multiple of page size");
  }

  struct user_regs_struct mmap_regs;
  ptrace(PTRACE_GETREGS, child, 0, &mmap_regs);
  __uint8_t flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (addr != 0)
	  flags |= MAP_FIXED;

  mmap_regs.rip = sysCall;
  mmap_regs.rax = 9;
  mmap_regs.rdi = addr;
  mmap_regs.rsi = length;
  mmap_regs.rdx = (__uint64_t) prot;
  mmap_regs.r10 = (__uint64_t) flags;
  mmap_regs.r8 = __UINT64_MAX__;
  mmap_regs.r9 = 0;

  ptrace(PTRACE_SETREGS, child, 0, &mmap_regs);
  single_step(child);

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child, 0, &regs);
  __int64_t mmap_location = (__int64_t) regs.rax;
  if (mmap_location == -1) {
	raise_error("mmap syscall exited with -1");
  }

  if (addr != 0 && (size_t) mmap_location != addr) {
	raise_error("failed to map at correct location");
  }
  return (__uint64_t) mmap_location;
}

void remote_munmap(pid_t child, __uint64_t sysCall, size_t addr, size_t length) {
  struct user_regs_struct syscall_regs;
  ptrace(PTRACE_GETREGS, child, 0, &syscall_regs);

  syscall_regs.rip = sysCall;
  syscall_regs.rax = 11;
  syscall_regs.rdi = addr;
  syscall_regs.rsi = length;

  ptrace(PTRACE_SETREGS, child, 0, &syscall_regs);
  single_step(child);

  struct user_regs_struct new_regs;
  ptrace(PTRACE_GETREGS, child, 0, &new_regs);
  if (new_regs.rax != 0) {
	  raise_error("failed to munmap");
  }
}

void remote_mremap(pid_t child, __uint64_t sysCall, size_t addr, size_t length, size_t new_addr) {
  if (addr == new_addr) {
	  return;
  }

  struct user_regs_struct syscall_regs;
  ptrace(PTRACE_GETREGS, child, 0, &syscall_regs);

  syscall_regs.rip = sysCall;
  syscall_regs.rax = 25;
  syscall_regs.rdi = addr;
  syscall_regs.rsi = length;
  syscall_regs.rdx = length;
  syscall_regs.r10 = (__uint64_t) MREMAP_MAYMOVE | MREMAP_FIXED;
  syscall_regs.r8 = new_addr;

  ptrace(PTRACE_SETREGS, child, 0, &syscall_regs);
  single_step(child);

  struct user_regs_struct new_regs;
  ptrace(PTRACE_GETREGS, child, 0, &new_regs);

  if ((__int64_t) new_regs.rax == -1) {
	  raise_error("failed to mremap");
  }

  if ((size_t) new_regs.rax != new_addr) {
    printf("%lu != %lu, remapped from %lu, length: %lu\n", (size_t) new_regs.rax, new_addr, addr, length);
	  raise_error("didn't mremap to correct location");
  }
}

void stream_memory(pid_t child, FILE* in, size_t addr, size_t length) {
  off_t remaining_size = length;
  char* buf = calloc(SYS_PAGE_SIZE, sizeof(char));
  while (remaining_size > 0) {
    off_t batch_size = min(SYS_PAGE_SIZE, remaining_size);
    off_t offset = addr + (length - remaining_size);

    fread(buf, SYS_PAGE_SIZE, 1, in);

    struct iovec local[1];
    local[0].iov_base = buf;
    local[0].iov_len = SYS_PAGE_SIZE;

    struct iovec remote[1];
    remote[0].iov_base = (void*) offset;
    remote[0].iov_len = batch_size;

    if (process_vm_writev(child, local, 2, remote, 1, 0) == 0) {
      raise_error("failed to write to process");
    }
    remaining_size -= batch_size;
  }

  free(buf);
}

procmaps_struct* find_map_named(procmaps_iterator* maps, char* name) {
  procmaps_struct* map_tmp = (void*)0;
  while ((map_tmp = pmparser_next(maps)) != (void*)0) {
	if (strcmp(get_map_name(map_tmp), name) == 0) {
	  return map_tmp;
	}
  }
  return (void*)0;
}

void restore_brk(pid_t child, __uint64_t sysCall, size_t brk_addr) {
  size_t orig_brk = remote_brk(child, sysCall, 0);
  size_t new_brk = remote_brk(child, sysCall, brk_addr);

  if (new_brk > orig_brk) {
	remote_munmap(child, sysCall, orig_brk, new_brk - orig_brk);
  }
}

pid_t receive_fork(FILE* in, __int32_t pass_to_child) {
  Result child_res = fork_frozen();
  if (child_res.loc == Child) {
	  raise_error("rehydrate failed"); // if it somehow gets to here, it means the rehydration to the client has failed. 
    // Everything related to the child process created by the server should already be deleted by now.
  }

  pid_t child = child_res.pid;

  procmaps_iterator* orig_maps = pmparser_parse(child);
  if (orig_maps == (void*)0) {
	  raise_error("failed to parse proc_map");
  }

  procmaps_struct* vdso_map = find_map_named(orig_maps, "[vdso]");
  if (vdso_map == (void*)0) {
	  raise_error("unable to find vdso map");
  }
  
  size_t vsdo_syscall_offset = try_to_find_syscall(child, (size_t) vdso_map->addr_start);
  __uint64_t vdso_syscall = ((size_t) vdso_map->addr_start) + vsdo_syscall_offset;

  procmaps_struct* map_tmp = (void*)0;
  while ((map_tmp = pmparser_next(orig_maps)) != (void*)0) {
    if (is_special_kernel_map(map_tmp) || map_tmp->length == 0) {
      continue;
    }
	  remote_munmap(child, vdso_syscall, (size_t) map_tmp->addr_start, map_tmp->length);
  }

  pmparser_free(orig_maps);

  procmaps_iterator* maps = pmparser_parse(child);
  if (maps == (void*)0) {
	 raise_error("failed to parse proc_map");
  }

  __uint8_t prot_all = PROT_READ | PROT_WRITE | PROT_EXEC;
  Command cmd;
  bool breakLoop = false;
  for (;;) {
    if (fread(&cmd, sizeof(Command), 1, in) == 0) {
      continue;
    }

    printf("%d\n", cmd.type);

    switch (cmd.type) {
      case PROCESS_STATE:
        restore_brk(child, vdso_syscall, cmd.cmds.ps.brk_address);

        break;

      case REMAP: ;
        procmaps_struct* matching_map = find_map_named(maps, cmd.cmds.rm.name);
        if (matching_map == (void*)0) {
          printf("%s\n", "no matching map to remap");
          continue;
        }
        
        if (cmd.cmds.rm.size != matching_map->length) {
          printf("%s\n", "size mismatch in remap");
        }

        remote_mremap(
          child,
          vdso_syscall,
          (size_t) matching_map->addr_start,
          (size_t) matching_map->length,
          cmd.cmds.rm.addr
        );

        if (strcmp(cmd.cmds.rm.name, "[vdso]") == 0) {
          vdso_syscall = (__uint64_t)(cmd.cmds.rm.addr + vsdo_syscall_offset);
        }

        break;

      case MAPPING:
        if (cmd.cmds.mp.addr == (void*)0) {
          raise_error("(void*)0 string");
        }

        size_t addr = remote_mmap_anon(child, vdso_syscall, (size_t) cmd.cmds.mp.addr, cmd.cmds.mp.size, prot_all);
        stream_memory(child, in, addr, cmd.cmds.mp.size);
        
        break;

      case RESUME_WITH_REGISTERS: ;
        struct user_regs_struct regs = cmd.cmds.rwr.user;

        regs.rax = (__uint64_t) pass_to_child; // resume from the raise(SIGSTOP) call that checks for a compatible rax.
        ptrace(PTRACE_SETREGS, child, 0, &regs);

        breakLoop = true;
        
        break;
    }

    if (breakLoop) {
      break;
    }
  }

  pmparser_free(maps);
  ptrace(PTRACE_DETACH, child, 0, 0); // stop tracing and restart executing.
  return child;
}

__int32_t wait_for_exit(pid_t child) {
  int status;
  waitpid(child, &status, 0);
  if (WIFEXITED(status)) {
	  return status;
  }
  printf("got status: %d\n", status);
  raise_error("a different wait status instead of exit");
  return -1;
}

// void yoyo(char* addr) {
//   int stream = connect_to_tcp_server(addr);
//   FILE* f_send = fdopen(dup(stream), "wb");
//   FILE* f_recv = fdopen(dup(stream), "rb");
//   Result res = remote_fork(f_send);
  
//   switch (res.loc) {
//     case Child: ;
//       FILE* child_send = fdopen(res.pid, "wb");

//       // do some work here

//       Result child_res = remote_fork(child_send);
//       fclose(child_send);

//       switch (child_res.loc) {
//         case Child:
//           return;
//         case Parent:
//           exit(0);
//       }      
//       break;
//     case Parent:
//       fclose(f_send);
//       break;
//   }

//   pid_t child = receive_fork(f_recv, 0);
//   int status = wait_for_exit(child);
//   fclose(f_recv);
//   close(stream);
//   exit(status);
// }

int raise_error(char* msg) {
  void* array[10];
  char** strings;
  size_t size;

  size = backtrace(array, 10); // get stack trace
  strings = backtrace_symbols(array, size); // get functions names from stack trace
  if (strings != (void*)0) {
	for (size_t i = 0; i < size; i++)
	  printf("%s\n", strings[i]);
  }

  free(strings); 
  printf("%s\n%s\n", msg, strerror(errno));
  exit(1);
}

char* const get_map_name(procmaps_struct* map) {
  return basename(map->pathname);
}

off_t min(off_t a, off_t b) {
  if (a > b) {
	return b;
  }
  return a;
}

