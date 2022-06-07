#ifndef REMOTE_FORK_H
#define REMOTE_FORK_H

#include <stdio.h>
#include <pmparser.h>
#include <stdbool.h>
#include <sys/user.h>

/* ---------- DEFINITIONS ---------- */

#define SYS_PAGE_SIZE 4096

#define FORCED_VDSO_TRANSFER false

/* ---------- ENUMS ---------- */

enum ForkLocation {
  Parent = 1,
  Child = 2,
};

/* ---------- STRUCTS ---------- */

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

typedef struct Mapping {
  char* name;
  bool readable;
  bool writable;
  bool executable;
  void* addr;
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

typedef struct Command {
  enum CommandType type;
  union cmds {
    ProcessState ps;
    Mapping mp;
    Remap rm;
    ResumeWithRegisters rwr;
  } cmds;
} Command;

typedef struct RegInfo {
  struct user_regs_struct regs;
} RegInfo;


typedef struct BytesArray {
  unsigned char* pointer;
  size_t size;
} BytesArray;

/* ---------- MAIN FUNCTIONS ---------- */

Result const remote_fork(FILE* out);

pid_t receive_fork(FILE* in, __int32_t pass_to_child);

__int32_t wait_for_exit(pid_t child);

// /*All in one*/
// void yoyo(char* addr);

/* ---------- UTILS ---------- */

/*A hacky way to throw an error and stops the entire program.*/
extern int raise_error(char* msg);

#endif // REMOTE_FORK_H
