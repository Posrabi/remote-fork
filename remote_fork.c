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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pmparser.h>
#include <remote_fork.h>

off_t const SYS_PAGE_SIZE = 4096;
bool const FORCED_VDSO_TRANSFER = false;

enum ForkLocation {
  Parent = 1,
  Child = 2,
};

typedef struct Result {
  enum ForkLocation loc;
  int raise_result;
  pid_t pid;
} Result;

typedef struct ProcessState {
  size_t brk_address; 
} ProcessState;

enum CommandType {
  PROCESS_STATE = 1,
  MAPPING = 2,
  REMAP = 3,
  RESUME_WITH_REGISTERS = 4,
};

typedef struct Command {
  enum CommandType type;
  union cmds {
    ProcessState ps;
    Mapping mp;
    Remap rm;
    ResumeWithRegisters rwr;
  } cmds;
} Command;

typedef struct Mapping {
  char* name;
  bool readable;
  bool writable;
  bool executable;
  size_t addr;
  off_t size;
} Mapping;

typedef struct Remap {
  char* name;
  size_t addr;
  off_t size;
} Remap;

typedef struct ResumeWithRegisters {
  size_t length;
} ResumeWithRegisters;


typedef struct RegInfo {
  struct user_regs_struct regs;
} RegInfo;


typedef struct BytesArray {
  unsigned char* pointer;
  size_t size;
} BytesArray;

BytesArray from_reg_info_to_bytes(RegInfo* ri) {
  BytesArray ba = {
    .pointer = &(ri->regs),
    .size = sizeof(ri->regs)
  };
  return ba;
}

RegInfo* from_bytes_to_reg_info(BytesArray* ba) {
  if (ba->size < sizeof(struct user_regs_struct)) {
    return NULL;
  }
  
  // if ((*(ba->pointer)) % ba->size != 0) {
  //   return NULL;
  // }
  RegInfo* ri;
  ri = malloc(sizeof(RegInfo));

  mempcpy(&(ri->regs), ba->pointer, ba->size);
  return ri;
}

int _prot(Mapping* m) {
  int prot = 0;
  if (m->readable) {
    prot |= PROT_READ;
  }
  if (m->writable) {
    prot |= PROT_WRITE;
  }
  if (m->executable) {
    prot |= PROT_EXEC;
  }

  return prot;
}


Result const remote_fork(FILE* out) {
  ProcessState const proc_state = {.brk_address = sbrk(0)};
  Result const fork_meta = fork_frozen();

  if (fork_meta.loc == Child) {
    // Write state over to child and then kill it
    write_state(out, fork_meta.pid, proc_state);
    kill(fork_meta.pid, SIGKILL);
  }
  
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
    Result const res = {.raise_result = raise_result, .loc = Child, .pid = getpid()};

    return res;
  } else {
    // Parent process. The pid here is the child' pid, not the parent which is what we want.
    int status;
    waitpid(pid, &status, WCONTINUED);

    if WIFSTOPPED(status) {
      Result const res = {.loc = Parent, .pid = pid};
      return res;
    }
    raise_error("couldn't trace child");
  }
};

int const kill_if_parent_dies() {
  return prctl(PR_SET_PDEATHSIG, SIGKILL);
}

// Remapping these are just too difficult.
bool const is_special_kernel_map(procmaps_struct* map) {
  char* const file_name = get_map_name(map);
  if (strcmp(file_name, "vdso") != 0 && strcmp(file_name, "vsyscall") != 0 && strcmp(file_name, "[vvar]") != 0 )  {
    return false;
  }
  return true;
}

bool const forced_transfer_kernel_map(procmaps_struct* map) {
  if (!FORCED_VDSO_TRANSFER) {
    return false;
  }

  char* const file_name = get_map_name(map);
  if (strcmp(file_name, "vdso") == 0) {
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
  if (m_name == NULL) {
    raise_error("a kernel map must have a name");
  }

  Remap const remap_cmd = {
    .name = m_name, 
    .addr = map->addr_start, 
    .size = map->length
  };
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
  Mapping const mapping = {
    .name = get_map_name(map),
    .readable = map->is_r,
    .writable = map->is_r,
    .executable = map->is_x,
    .addr = map->addr_start,
    .size = map->length,
  };
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
  __uint8_t* buf = calloc(sizeof(__uint8_t), SYS_PAGE_SIZE);
  while (remaining_size > 0) {
    off_t read_size = min(remaining_size, SYS_PAGE_SIZE);
    off_t offset = map->addr_start + (map->length - remaining_size);

    struct iovec local[1];
    local[0].iov_base = buf;
    local[0].iov_len = read_size;
    
    struct iovec remote[1];
    remote[0].iov_base = offset;
    remote[0].iov_len = read_size;

    ssize_t wrote = process_vm_readv(child, local, 2, remote, 1, 0);
    if (wrote == 0) {
      raise_error("failed to read from other process");
    }

    if (fwrite(buf, SYS_PAGE_SIZE, 1, out) == 0) {
      raise_error("failed writing regular map");
    }
    remaining_size -= read_size;
  }

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

  procmaps_iterator* maps = pmparser_parse(child);
  if (maps == NULL) {
    raise_error("error getting proc maps");
  }

  procmaps_struct* map_tmp = NULL;
  while ((map_tmp = pmparser_next(maps)) != NULL) {
    if (should_skip_map(map_tmp)) {
      continue;
    }

    if (is_special_kernel_map(map_tmp) && !forced_transfer_kernel_map(map_tmp)) {
      write_special_kernel_map(out, map_tmp);
    } else {
      write_regular_map(out, child, map_tmp);
    }
  }
  pmparser_free(maps);

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child, NULL, &regs);

  RegInfo ri = {
    .regs = regs
  };

  BytesArray rb = from_reg_info_to_bytes(&ri);
  Command cmd = {
    .type = RESUME_WITH_REGISTERS,
    .cmds = {
      .rwr = {
        .length = sizeof(struct user_regs_struct),
      }
    }
  };

  if (fwrite(&cmd, sizeof(Command), 1, out) == 0) {
    raise_error("error writing registers command");
  }
  
  if (fwrite(&rb, sizeof(RegInfo), 1, out) == 0) {
    raise_error("error writing registers");
  }
}

// void print_maps_info(procmaps_struct* map) {
//   pmparser_print(map, 0);
//   printf("\\n~~~~~~~~~~~~~~~~~~~~~~~~~\n");
// }

void single_step(pid_t child) {
  ptrace(PTRACE_SINGLESTEP, child);
  int status;
  waitpid(child, &status, NULL);

  if (!WIFSTOPPED(status)) {
    raise_error("couldn't trace child");
  }
}

size_t try_to_find_syscall(pid_t child, size_t addr) {
  int* buf = calloc(sizeof(u_int8_t), SYS_PAGE_SIZE);
  
  struct iovec local[1];
  local[0].iov_base = buf;
  local[0].iov_len = SYS_PAGE_SIZE;
  
  struct iovec remote[1];
  remote[0].iov_base = addr;
  remote[0].iov_len = SYS_PAGE_SIZE;

  ssize_t wrote = process_vm_readv(child, local, 2, remote, 1, 0);
  if (wrote == 0) {
    raise_error("error writing from remote process");
  }

  u_int8_t syscalls[2] = {0x0f, 0x05};
  for (size_t i = 0; i < SYS_PAGE_SIZE; i += sizeof(syscalls)) {
    if (*(buf + i) == syscalls) {
      return i;
    }
  }

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
  if (addr != 0) {
    flags |= MAP_FIXED;
  }

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
    raise_error("didn't mremap to correct location");
  }
}

void stream_memory(pid_t child, FILE* in, size_t addr, size_t length) {
  off_t remaining_size = length;
  __uint8_t* buf = calloc(sizeof(__uint8_t), SYS_PAGE_SIZE);
  while (remaining_size > 0) {
    off_t batch_size = min(SYS_PAGE_SIZE, remaining_size);
    off_t offset = addr + (length - remaining_size);

    fread(buf, SYS_PAGE_SIZE, 1, in);

    struct iovec local[1];
    local[0].iov_base = buf;
    local[0].iov_len = SYS_PAGE_SIZE;

    struct iovec remote[1];
    remote[0].iov_base = offset;
    remote[0].iov_len = batch_size;

    if (process_vm_writev(child, local, 2, remote, 1, 0) == 0) {
      raise_error("failed to write to process");
    }
    remaining_size -= batch_size;
  }

  free(buf);
}

procmaps_struct* find_map_named(procmaps_iterator* maps, char* name) {
  procmaps_struct* map_tmp = NULL;
  while ((map_tmp = pmparser_next(maps)) != NULL) {
    if (strcmp(get_map_name(map_tmp), name)) {
      return map_tmp;
    }
  }
  return NULL;
}

void restore_brk(pid_t child, __uint64_t sysCall, size_t brk_addr) {
  size_t orig_brk = remote_brk(child, sysCall, 0);
  size_t new_brk = remote_brk(child, sysCall, brk_addr);

  if (new_brk > orig_brk) {
    remote_munmap(child, sysCall, orig_brk, new_brk - orig_brk);
  }
}

pid_t receive_fork(FILE* in, __int32_t pass_to_child) {
  Result childRes = fork_frozen();
  if (childRes.loc == Child) {
    raise_error("rehydrate failed");
  }
  pid_t child = childRes.pid;

  procmaps_iterator* orig_maps = pmparser_parse(child);
  procmaps_struct* vdso_map = find_map_named(orig_maps, "[vdso]");
  if (vdso_map == NULL) {
    raise_error("unable to find vdso map");
  }
  
  size_t vsdo_syscall_offset = try_to_find_syscall(child, vdso_map->addr_start);
  __uint64_t vdso_syscall = vdso_map->addr_start + vsdo_syscall_offset;
  
  procmaps_struct* map_tmp = NULL;
  while ((map_tmp = pmparser_next(orig_maps)) != NULL) {
    if (is_special_kernel_map(map_tmp) || map_tmp->length == 0) {
      continue;
    }
    remote_munmap(child, vdso_syscall, map_tmp->addr_start, map_tmp->length);
  }

  pmparser_free(orig_maps);

  procmaps_iterator* maps = pmparser_parse(child);
  __uint8_t prot_all = PROT_READ | PROT_WRITE | PROT_EXEC;
  Command cmd;
  for (;;) {
    if (fread(&cmd, sizeof(Command), 1, in) == 0) {
      continue;
    }

    switch (cmd.type) {
      case PROCESS_STATE:
        restore_brk(child, vdso_syscall, cmd.cmds.ps.brk_address);

      case REMAP:
        procmaps_struct* matching_map = find_map_named(maps, cmd.cmds.rm.name);
        if (matching_map == NULL) {
          printf("%s\n", "no matching map to remap");
          continue;
        }
        

        if (cmd.cmds.rm.size != matching_map->length) {
          printf("%s\n", "size mismatch in remap");
        }

        remote_mremap(
          child,
          vdso_syscall,
          matching_map->addr_start,
          matching_map->addr_end,
          cmd.cmds.rm.addr
        );

        if (strcmp(cmd.cmds.rm.name, "[vdso]") == 0) {
          vdso_syscall = (__uint64_t)(cmd.cmds.rm.addr + vsdo_syscall_offset);
        }
        break;

      case MAPPING:
        if (cmd.cmds.mp.addr == NULL) {
          raise_error("null string");
        }

        size_t addr = remote_mmap_anon(child, vdso_syscall, cmd.cmds.mp.addr, cmd.cmds.mp.size, prot_all);
        stream_memory(child, in, addr, cmd.cmds.mp.size);
        break;

      case RESUME_WITH_REGISTERS:
        char* reg_bytes = calloc(sizeof(__uint8_t), cmd.cmds.rwr.length);
        fread(reg_bytes, cmd.cmds.rwr.length, 1, in);

        BytesArray ba = {
          .pointer = reg_bytes,
          .size = cmd.cmds.rwr.length
        };
        RegInfo* reg_info = from_bytes_to_reg_info(&ba);
        if (reg_info == NULL) {
          raise_error("unable to deserialize reg_info");
        }

        reg_info->regs.rax = (__uint64_t) pass_to_child;
        ptrace(PTRACE_SETREGS, child, 0, &(reg_info->regs));

        free(reg_info);
        free(reg_bytes);
        break;
    }
  }

  pmparser_free(maps);
  ptrace(PTRACE_DETACH, child, 0, 0);
  return child;
}

__int32_t wait_for_exit(pid_t child) {
  int status;
  waitpid(child, &status, NULL);
  if (WIFEXITED(status)) {
    return status;
  }
  raise_error("a different wait status instead of exit");
}

void yoyo(char* addr) {
  int stream = connect_to_tcp_server(addr);
  FILE* f_send = fdopen(dup(stream), "wb");
  FILE* f_recv = fdopen(dup(stream), "rb");
  Result res = remote_fork(f_send);
  
  switch (res.loc) {
    case Child:
      FILE* child_send = fdopen(res.pid, "wb");

      // do some work here

      Result child_res = remote_fork(child_send);
      fclose(child_send);

      switch (child_res.loc) {
        case Child:
          return;
        case Parent:
          exit(0);
      }      
      break;
    case Parent:
      fclose(f_send);
      break;
  }

  pid_t child = receive_fork(f_recv, 0);
  int status = wait_for_exit(child);
  exit(status);
}

int raise_error(char* msg) {
  void* array[10];
  char** strings;
  size_t size;

  size = backtrace(array, 10); // get stack trace
  strings = backtrace_symbols(array, size); // get functions names from stack trace
  if (strings != NULL) {
    for (size_t i = 0; i < size; i++)
      printf("%s\n", strings[i]);
  }

  free(strings); 
  printf("%s\n", msg);

  return 1/0;
}

char* const get_map_name(procmaps_struct* map) {
  return strrchr(map->pathname, '/');
}

off_t min(off_t a, off_t b) {
  if (a > b) {
    return b;
  }
  return a;
}

int connect_to_tcp_server(char* server_addr) {
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    raise_error("unable to create socket");
  }
  
  unsigned short port = 8081;
  struct sockaddr_in server;
  server.sin_addr.s_addr = inet_addr(server_addr);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if (connect(sock, (struct sockaddr*) &server, sizeof(server)) < 0) {
    raise_error("unable to connect to server");
  }

  return sock;
}
