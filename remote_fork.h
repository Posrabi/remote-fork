#include <stdio.h>
#include <pmparser.h>
#include <stdbool.h>

#ifndef REMOTE_FORK_H
#define REMOTE_FORK_H

/* ---------- DEFINITIONS ---------- */

#define SYS_PAGE_SIZE 4096

#define FORCED_VDSO_TRANSFER false

/* ---------- ENUMS ---------- */

/*Where is the process.*/
enum ForkLocation;

/*Enum to help with deserializing commands.*/
enum CommandType;

/* ---------- Structs ---------- */

/*Generic struct with fork locations, pid and raise_result*/
typedef struct Result;

/*Current state*/
typedef struct ProcessState;

/*Representing memory mappings.*/
typedef struct Mapping;

typedef struct Remap;

typedef struct ResumeWithRegisters;

/*Generic bytes array with head pointer and length.*/
typedef struct BytesArray;
BytesArray from_reg_info_to_bytes(RegInfo* ri);

/*Struct containing user_regs_struct*/
typedef struct RegInfo;
/*Create RegInfo from BytesArray, need to free when done using.*/
RegInfo* from_bytes_to_reg_info(BytesArray* ba);

int _prot(Mapping* m);

/* ---------- Main functions ---------- */

Result const remote_fork(FILE* out);

Result const fork_frozen();

/*Kill the child process if the parent dies.*/
int const kill_if_parent_dies();

bool const is_special_kernel_map(procmaps_struct* map);

bool const forced_transfer_kernel_map(procmaps_struct* map);

bool const should_skip_map(procmaps_struct* map);

void write_special_kernel_map(FILE* out, procmaps_struct* map);

void write_regular_map(FILE* out, pid_t child, procmaps_struct* map);

void write_state(FILE* out, pid_t child, ProcessState proc_state);

void single_step(pid_t child);

size_t try_to_find_syscall(pid_t child, size_t addr);

/* ---------- Replicating Linux's memory mappings ---------- */

size_t remote_brk(pid_t child, __uint64_t sysCall, size_t brk);

size_t remote_mmap_anon(pid_t child, __uint64_t sysCall, size_t addr, size_t length, int32_t prot);

void remote_munmap(pid_t child, __uint64_t sysCall, size_t addr, size_t length);

void remote_mremap(pid_t child, __uint64_t sysCall, size_t addr, size_t length, size_t new_addr);

void stream_memory(pid_t child, FILE* in, size_t addr, size_t length);

procmaps_struct* find_map_named(procmaps_iterator* maps, char* name);

void restore_brk(pid_t child, __uint64_t sysCall, size_t brk_addr);

pid_t receive_fork(FILE* in, __int32_t pass_to_child);

__int32_t wait_for_exit(pid_t child);

/*All in one*/
void yoyo(char* addr);

/* ---------- UTILS ---------- */

/*A hacky way to throw an error and stops the entire program.*/
int raise_error(char* msg);

char* const get_map_name(procmaps_struct* map);

off_t min(off_t a, off_t b);

int connect_to_tcp_server(char* server_addr);

#endif // REMOTE_FORK_H
