// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: zhangziheng0525@163.com
//
// user-mode code for the process image

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "proc_image.h"
#include "resource_image.skel.h"
#include "syscall_image.skel.h"
#include "lock_image.skel.h"
#include "keytime_image.skel.h"
#include "schedule_image.skel.h"
#include "mfutex.skel.h"
#include "hashmap.h"
#include "helpers.h"
#include "trace_helpers.h"
#include "syscall_helpers.h"

static int prev_image = 0;
static volatile bool exiting = false;
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";
static struct env {
	int ignore_tgid;
	bool output_resourse;
	bool output_schedule;
	bool create_thread;
	bool exit_thread;
    bool enable_resource;
	bool first_rsc;
	u64 sum_delay;
	u64 sum_count;
	u64 max_delay;
	u64 min_delay;
	bool enable_hashmap;
	bool enable_syscall;
	bool enable_lock;
	int max_args;
	bool enable_keytime;
	int stack_count;
	bool enable_schedule;
	int rsc_prev_tgid;
	int kt_prev_tgid;
	int lock_prev_tgid;
	int sc_prev_tgid;
	char hostname[64];
	bool enable_mfutex;
} env = {
	.output_resourse = false,
	.output_schedule = false,
	.create_thread = false,
	.exit_thread = false,
    .enable_resource = false,
	.first_rsc = true,
	.sum_delay = 0,
	.sum_count = 0,
	.max_delay = 0,
	.min_delay = 0,
	.enable_hashmap = false,
	.enable_syscall = false,
	.enable_lock = false,
	.max_args = DEFAULT_MAXARGS,
	.enable_keytime = false,
	.stack_count = 0,
	.enable_schedule = false,
	.rsc_prev_tgid = 0,
	.kt_prev_tgid = 0,
	.lock_prev_tgid = 0,
	.sc_prev_tgid = 0,
	.hostname = "",
	.enable_mfutex = false,
};

struct hashmap *map = NULL;
struct resource_image_bpf *resource_skel = NULL;
struct syscall_image_bpf *syscall_skel = NULL;
struct lock_image_bpf *lock_skel = NULL;
struct keytime_image_bpf *keytime_skel = NULL;
struct schedule_image_bpf *schedule_skel = NULL;
struct mfutex_bpf *mfutex_skel = NULL;


static int scmap_fd;
static int rscmap_fd;
static int lockmap_fd;
static int ktmap_fd;
static int schedmap_fd;
static int mfutexmap_fd;

static struct timespec prevtime;
static struct timespec currentime;

char *lock_status[] = {"", "mutex_req", "mutex_lock", "mutex_unlock",
						   "rdlock_req", "rdlock_lock", "rdlock_unlock",
						   "wrlock_req", "wrlock_lock", "wrlock_unlock",
						   "spinlock_req", "spinlock_lock", "spinlock_unlock"};
char *mfutex_type[] = {"","MUTEX","RW_LOCK","SPIN_LOCK","RCU_LOCK","FUTEX_LOCK"};

char *keytime_type[] = {"", "exec_enter", "exec_exit", 
						    "exit", 
						    "forkP_enter", "forkP_exit",
						    "vforkP_enter", "vforkP_exit",
						    "createT_enter", "createT_exit",
							"onCPU", "offCPU",};

static struct ksyms *ksyms = NULL;
static struct syms_cache *sched_syms_cache = NULL;
static struct ksyms *sched_ksyms = NULL;


char *task_state[] = {"TASK_RUNNING", "TASK_INTERRUPTIBLE", "TASK_UNINTERRUPTIBLE", 
                      "", "__TASK_STOPPED", "", "", "", "__TASK_TRACED"};
char *timestamp_state[] = {"OFFCPU", "ONCPU", "WAKEUP", "WAKEUPNEW", "SYSCALL"};

//u32 syscalls[NR_syscalls] = {};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
	{ "all", 'a', NULL, 0, "Attach all eBPF functions(but do not start)" },
    { "resource", 'r', NULL, 0, "Attach eBPF functions about resource usage(but do not start)" },
	{ "syscall", 's', NULL, 0, "Attach eBPF functions about syscall sequence(but do not start)" },
	{ "lock", 'l', NULL, 0, "Attach eBPF functions about lock(but do not start)" },
	{ "keytime", 'k', NULL, 0, "Attach eBPF functions about keytime(but do not start)" },
	{ "schedule", 'S', NULL, 0, "Attach eBPF functions about schedule (but do not start)" },
	{ "mfutex", 'm', NULL, 0, "Attach eBPF functions about mfutex (but do not start)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'a':
				env.enable_resource = true;
				env.enable_syscall = true;
				env.enable_lock = true;
				env.enable_keytime = true;
				env.enable_schedule = true;
				env.enable_mfutex = true;
				break;
        case 'r':
                env.enable_resource = true;
                break;
		case 's':
				env.enable_syscall = true;
                break;
		case 'l':
                env.enable_lock = true;
                break;
		case 'k':
				env.enable_keytime = true;
				break;
		case 'S':
				env.enable_schedule = true;
				break;
		case 'm':
				env.enable_mfutex = true;
				break;		
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
        default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

static int print_resource(struct bpf_map *map,int rscmap_fd)
{
	int err,key = 0;
	struct rsc_ctrl rsc_ctrl ={};

	err = bpf_map_lookup_elem(rscmap_fd,&key,&rsc_ctrl);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	if(!rsc_ctrl.rsc_func)
		return 0;
	if(env.first_rsc){
		env.first_rsc = false;
		goto delete_elem;
	}
	
	struct proc_id lookup_key = {-1,-1}, next_key;
	int fd = bpf_map__fd(map);
	struct total_rsc event;
	float pcpu,pmem;
	double read_rate,write_rate;
	unsigned long memtotal = sysconf(_SC_PHYS_PAGES);
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
	long long unsigned int interval;
	int rsc_cur_tgid = 0;

	if(rsc_ctrl.target_tgid != -1)	rsc_cur_tgid = 2;
	else	rsc_cur_tgid = 1;
    
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		if(prev_image != RESOURCE_IMAGE || env.rsc_prev_tgid != rsc_cur_tgid){
			printf("RESOURCE ------------------------------------------------------------------------------------------------\n");
			printf("%-8s  ","TIME");
			if(rsc_ctrl.target_tgid != -1){
				printf("%-6s  ","TGID");
				env.rsc_prev_tgid = 2;
			}else{
				env.rsc_prev_tgid = 1;
			}
			printf("%-6s  %-6s  %-6s  %-6s  %-12s  %-12s\n","PID","CPU-ID","CPU(%)","MEM(%)","READ(kb/s)","WRITE(kb/s)");
			prev_image = RESOURCE_IMAGE;
		}
			
		err = bpf_map_lookup_elem(fd, &next_key, &event);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		
		clock_gettime(CLOCK_REALTIME, &currentime);
		interval = currentime.tv_nsec-prevtime.tv_nsec+(currentime.tv_sec-prevtime.tv_sec)*1000000000;

		if(interval>0 && memtotal>0 && event.time>0){
			pcpu = (100.0*event.time)/interval;
			pmem = (100.0*event.memused)/memtotal;
			read_rate = (1.0*event.readchar)/1024/((1.0*event.time)/1000000000);            // kb/s
			write_rate = (1.0*event.writechar)/1024/((1.0*event.time)/1000000000);          // kb/s
		}else{
			goto next_elem;
		}
		
		if(pcpu<=100 && pmem<=100){
			printf("%02d:%02d:%02d  ",hour,min,sec);
			if(rsc_ctrl.target_tgid != -1)	printf("%-6d  ",event.tgid);
			printf("%-6d  %-6d  %-6.3f  %-6.3f  %-12.2lf  %-12.2lf\n",
					event.pid,event.cpu_id,pcpu,pmem,read_rate,write_rate);
		}

next_elem:
		lookup_key = next_key;
	}

delete_elem:
    lookup_key.pid = -1;	
	lookup_key.cpu_id = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	// 获取当前高精度时间
    clock_gettime(CLOCK_REALTIME, &prevtime);
	env.output_resourse = false;

	return 0;
}

// static void print_offcpu_map()
// {
// 	struct offcpu_key_t lookup_key = {}, next_key;
// 	const struct ksym *ksym;
// 	const struct syms *syms;
// 	const struct sym *sym;
// 	int err, i, ifd, sfd;
// 	unsigned long *ip;
// 	struct offcpu_val_t val;
// 	struct sym_info sinfo;
// 	int idx;

// 	ip = calloc(127, sizeof(*ip));
// 	if (!ip) {
// 		printf("7\n");

// 		fprintf(stderr, "failed to alloc ip\n");
// 		return;
// 	}
// 		printf("8\n");
// 	ifd = bpf_map__fd(schedule_skel->maps.offcpu_info);
// 	sfd = bpf_map__fd(schedule_skel->maps.stackmap);
// 	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
// 		printf("4\n");

// 		idx = 0;

// 		err = bpf_map_lookup_elem(ifd, &next_key, &val);
// 		if (err < 0) {
// 			fprintf(stderr, "failed to lookup info: %d\n", err);
// 			goto cleanup;
// 		}
// 		lookup_key = next_key;
// 		if (val.delta == 0)
// 			continue;
// 		if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0) {
// 			fprintf(stderr, "    [Missed Kernel Stack]\n");
// 			goto print_ustack;
// 		}

// 		for (i = 0; i < 127 && ip[i]; i++) {
// 			printf("index: %d\n", i);
// 			ksym = ksyms__map_addr(sched_ksyms, ip[i]);
// 			// if (!env.verbose) {
// 			// 	printf("    %s\n", ksym ? ksym->name : "unknown");
// 			// } 
// 			// else {
// 				if (ksym)
// 					printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name, ip[i] - ksym->addr);
// 				else
// 					printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
// 			// }
// 		}

// print_ustack:
// 		printf("5\n");

// 		if (next_key.user_stack_id == -1)
// 			goto skip_ustack;

// 		if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
// 			fprintf(stderr, "    [Missed User Stack]\n");
// 			goto skip_ustack;
// 		}

// 		syms = syms_cache__get_syms(sched_syms_cache, next_key.tgid);
// 		if (!syms) {
// 			// if (!env.verbose) {
// 			// 	fprintf(stderr, "failed to get syms\n");
// 			// } 
// 			// else {
// 				for (i = 0; i < 127 && ip[i]; i++)
// 					printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
// 			// }
// 			goto skip_ustack;
// 		}
// 		for (i = 0; i < 127 && ip[i]; i++) {
// 			// if (!env.verbose) {
// 			// 	sym = syms__map_addr(syms, ip[i]);
// 			// 	if (sym)
// 			// 		printf("    %s\n", sym->name);
// 			// 	else
// 			// 		printf("    [unknown]\n");
// 			// } 
// 			// else {
// 				printf("    #%-2d 0x%016lx", idx++, ip[i]);
// 				err = syms__map_addr_dso(syms, ip[i], &sinfo);
// 				if (err == 0) {
// 					if (sinfo.sym_name)
// 						printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
// 					printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
// 				}
// 				printf("\n");
// 			// }
// 		}

// skip_ustack:
// 		printf("    %-16s cpu id: %d    %s (%d)\n", "-", val.cpu, val.comm, next_key.pid);
// 		printf("        %lld\n\n", val.delta);
// 		printf("        %s\n\n", task_state[val.state]);
// 	}

// cleanup:
// 	free(ip);
// }
// static void print_wakeup_map()
// {
// 	struct wakeup_key_t lookup_key = {}, next_key;
// 	int err, i, wakeupfd, stack_traces_fd;
// 	unsigned long *ip;
// 	const struct ksym *ksym;
// 	__u64 val;

// 	ip = calloc(127, sizeof(*ip));
// 	if (!ip) {
// 		fprintf(stderr, "failed to alloc ip\n");
// 		return;
// 	}

// 	wakeupfd = bpf_map__fd(schedule_skel->maps.wakeup_duration);
// 	stack_traces_fd = bpf_map__fd(schedule_skel->maps.stackmap);

// 	while (!bpf_map_get_next_key(wakeupfd, &lookup_key, &next_key)){
// 		err = bpf_map_lookup_elem(wakeupfd, &next_key, &val);
// 		if (err < 0) {
// 			fprintf(stderr, "failed to lookup info: %d\n", err);
// 			free(ip);
// 			return;
// 		}
// 		printf("\n	%-16s %s\n", "target:", next_key.target_proc_comm);
// 		lookup_key = next_key;

// 		err = bpf_map_lookup_elem(stack_traces_fd, &next_key.wakeup_kern_stack_id, ip);
// 		if (err < 0) {
// 			fprintf(stderr, "missed kernel stack: %d\n", err);
// 		}
// 		for (i = 0; i < 127 && ip[i]; i++) {
// 			ksym = ksyms__map_addr(ksyms, ip[i]);
// 			if (ksym)
// 				printf("	%-16lx %s+0x%lx\n", ip[i], ksym->name, ip[i] - ksym->addr);
// 			else
// 				printf("	%-16lx Unknown\n", ip[i]);
// 		}
// 		printf("	%16s %s\n","waker:", next_key.waker_proc_comm);
// 		/*to convert val in microseconds*/
// 		val /= 1000;
// 		printf("	%lld\n", val);
// 	}

// 	free(ip);
// }
static int print_schedule(void *ctx, void *data,unsigned long data_sz)
{
	switch(data_sz)
	{
		case sizeof(struct offcpu_val_t):
			struct offcpu_val_t *offcpu_val = (struct offcpu_val_t*)data;
			printf("data size: %ld   kern id: %d   user id: %d\n", data_sz, offcpu_val->kern_stack_id, offcpu_val->user_stack_id);
			break;
		case sizeof(struct wakeup_value_t):
			struct wakeup_value_t *wakeup_val = (struct wakeup_value_t*)data;
			printf("data size: %ld   kern id: %d   user id: %d\n", data_sz, wakeup_val->wakeup_kern_stack_id, wakeup_val->wakeup_user_stack_id);
			break;		
		case sizeof(struct timestamp_t):
			struct timestamp_t *timestamp_val = (struct timestamp_t*)data;
			printf("data size: %ld   [%s] timestamp: %lld\n", data_sz, timestamp_state[timestamp_val->ts_type], timestamp_val->timestamp);
			break;
	}
	
	return 0;
}
// static int print_schedule(struct bpf_map *proc_map,struct bpf_map *target_map,struct bpf_map *sys_map,int schedmap_fd)
// {
// 	int err,key = 0;
// 	struct sched_ctrl sched_ctrl ={};

// 	err = bpf_map_lookup_elem(schedmap_fd,&key,&sched_ctrl);
// 	if (err < 0) {
// 		fprintf(stderr, "failed to lookup infos: %d\n", err);
// 		return -1;
// 	}
// 	if(!sched_ctrl.sched_func)	return 0;
	
// 	struct proc_id lookup_key = {-1}, next_key;
// 	int l_key = -1, n_key;
// 	int proc_fd = bpf_map__fd(proc_map);
// 	int target_fd = bpf_map__fd(target_map);
// 	// int tg_fd = bpf_map__fd(tg_map);
// 	int sys_fd = bpf_map__fd(sys_map);
// 	struct schedule_event proc_event;
// 	struct sum_schedule sys_event;
// 	time_t now = time(NULL);
// 	struct tm *localTime = localtime(&now);
//     int hour = localTime->tm_hour;
//     int min = localTime->tm_min;
//     int sec = localTime->tm_sec;
// 	u64 proc_avg_delay;
// 	u64 target_avg_delay;
// 	u64 sys_avg_delay;
// 	int sched_cur_tgid = 0;

// 	// if(sched_ctrl.target_tgid != -1)	sched_cur_tgid = 2;
// 	// else	sched_cur_tgid = 1;
	
// 	if(prev_image != SCHEDULE_IMAGE){
// 		printf("SCHEDULE ----------------------------------------------------------------------------------------------------------------------\n");
// 		printf("%-8s  ","TIME");
// 		// if(sched_ctrl.target_tgid != -1){
// 		// 	printf("%-6s  ","TGID");
// 		// 	env.sched_prev_tgid = 2;
// 		// }else{
// 		// 	env.sched_prev_tgid = 1;
// 		// }
// 		printf("%-6s  %-4s  %s\n","PID","PRIO","| P_AVG_DELAY(ms) S_AVG_DELAY(ms) | P_MAX_DELAY(ms) S_MAX_DELAY(ms) | P_MIN_DELAY(ms) S_MIN_DELAY(ms) |");
// 		prev_image = SCHEDULE_IMAGE;
// 	}

// 	if(sched_ctrl.target_pid==-1){
// 		while (!bpf_map_get_next_key(proc_fd, &lookup_key, &next_key)) {
// 			err = bpf_map_lookup_elem(proc_fd, &next_key, &proc_event);
// 			if (err < 0) {
// 				fprintf(stderr, "failed to lookup infos: %d\n", err);
// 				return -1;
// 			}
// 			proc_avg_delay = proc_event.sum_delay/proc_event.count;

// 			err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
// 			if (err < 0) {
// 				fprintf(stderr, "failed to lookup infos: %d\n", err);
// 				return -1;
// 			}
// 			sys_avg_delay = sys_event.sum_delay/sys_event.sum_count;

// 			printf("%02d:%02d:%02d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
// 					hour,min,sec,proc_event.pid,proc_event.prio,proc_avg_delay/1000000.0,sys_avg_delay/1000000.0,
// 					proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
			
// 			lookup_key = next_key;
// 		}
// 	}
// 	// else if(sched_ctrl.target_pid!=-1){
// 	// 	err = bpf_map_lookup_elem(target_fd, &key, &proc_event);
// 	// 	if (err < 0) {
// 	// 		fprintf(stderr, "failed to lookup infos: %d\n", err);
// 	// 		return -1;
// 	// 	}

// 	// 	if(proc_event.count != 0){	
// 	// 		target_avg_delay = proc_event.sum_delay/proc_event.count;
			
// 	// 		err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
// 	// 		if (err < 0) {
// 	// 			fprintf(stderr, "failed to lookup infos: %d\n", err);
// 	// 			return -1;
// 	// 		}
// 	// 		sys_avg_delay = sys_event.sum_delay/(sys_event.sum_count==0?1:sys_event.sum_count);

// 	// 		printf("%02d:%02d:%02d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
// 	// 				hour,min,sec,proc_event.pid,proc_event.prio,target_avg_delay/1000000.0,sys_avg_delay/1000000.0,
// 	// 				proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
// 	// 	}
// 	// }


	
// 	// else if(sched_ctrl.target_pid==-1 && sched_ctrl.target_tgid!=-1){
// 	// 	while (!bpf_map_get_next_key(tg_fd, &l_key, &n_key)) {
// 	// 		err = bpf_map_lookup_elem(tg_fd, &n_key, &proc_event);
// 	// 		if (err < 0) {
// 	// 			fprintf(stderr, "failed to lookup infos: %d\n", err);
// 	// 			return -1;
// 	// 		}
// 	// 		proc_avg_delay = proc_event.sum_delay/proc_event.count;

// 	// 		err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
// 	// 		if (err < 0) {
// 	// 			fprintf(stderr, "failed to lookup infos: %d\n", err);
// 	// 			return -1;
// 	// 		}
// 	// 		sys_avg_delay = sys_event.sum_delay/sys_event.sum_count;

// 	// 		printf("%02d:%02d:%02d  %-6d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
// 	// 				hour,min,sec,proc_event.tgid,proc_event.pid,proc_event.prio,proc_avg_delay/1000000.0,sys_avg_delay/1000000.0,
// 	// 				proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
			
// 	// 		l_key = n_key;
// 	// 	}
// 	// }

// 	env.output_schedule = false;

// 	return 0;
// }
static long softirq_count = 0;
static int print_syscall(void *ctx, void *data,unsigned long data_sz)
{
	switch(data_sz)
	{
		case sizeof(struct syscall_val_t):
			struct syscall_val_t* syscall_val = (struct syscall_val_t*)data;
			printf("syscall time: %lld   syscall: %s   duration: %lld  ret: %d\n", syscall_val->timestamp, syscall_val->syscall_id<syscall_names_size?syscall_names[syscall_val->syscall_id]:"[Unknow syscall]", syscall_val->duration, syscall_val->ret);
			break;
		case sizeof(struct softirq_val_t):
			softirq_count++;
			struct softirq_val_t* soft_val = (struct softirq_val_t*)data;
			printf("softirq time: %lld   softirq: %s   duration: %lld  count: %d\n", soft_val->timestamp, soft_val->vec_nr<NR_SOFTIRQS?vec_names[soft_val->vec_nr]:"[Unknow softirq]", soft_val->duration, softirq_count);
			break;
		case sizeof(struct hardirq_val_t):
			struct hardirq_val_t* hardirq_val = (struct hardirq_val_t*)data;
			printf("hardirq time: %lld    hardirq: %s    duration: %lld\n", hardirq_val->timestamp, hardirq_val->hardirq_name, hardirq_val->duration);
			break;
	}
	
	return 0;
}

static int print_lock(void *ctx, void *data,unsigned long data_sz)
{
	const struct lock_event *e = data;
	int lock_cur_tgid = 0;

	if(e->tgid != -1)	lock_cur_tgid = 2;
	else	lock_cur_tgid = 1;
	
	if(prev_image != LOCK_IMAGE || env.lock_prev_tgid != lock_cur_tgid){
        printf("USERLOCK ------------------------------------------------------------------------------------------------\n");
        printf("%-15s  ","TIME");
		if(e->tgid != -1){
			printf("%-6s  ","TGID");
			env.lock_prev_tgid = 2;
		} else {
			env.lock_prev_tgid = 1;
		}
		printf("%-6s  %-15s  %s\n","PID","LockAddr","LockStatus");
		prev_image = LOCK_IMAGE;
    }

	printf("%-15lld  ",e->time);
	if(e->tgid != -1)	printf("%-6d  ",e->tgid);
	printf("%-6d  %-15lld  ",e->pid,e->lock_ptr);
	if(e->lock_status==2 || e->lock_status==5 || e->lock_status==8 || e->lock_status==11){
		printf("%s-%d\n",lock_status[e->lock_status],e->ret);
	}else{
		printf("%s\n",lock_status[e->lock_status]);
	}

	return 0;
}

static int print_mfutex(void *ctx, void *data,unsigned long data_sz)
{
	const struct per_lock_event *e = data;
	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
	printf("%02d:%02d:%02d   ",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
	int type = e->type;
	if(type == MUTEX_FLAG){
		printf("%-12s  0x%-8x  %-11llu  %-11lu  %-16llu  %-10d\n",mfutex_type[e->type],e->lock_ptr,e->last_owner,e->last_hold_delay,e->start_hold_time,e->owner);
		printf("%-81s","");
		int err,record_lock_fd =bpf_map__fd(mfutex_skel->maps.record_lock);
		struct record_lock_key lookup_key1 = {-1,-1}, next_key;
		while(!bpf_map_get_next_key(record_lock_fd, &lookup_key1, &next_key)){
			// printf("next_key:%x target_ptr:%x\n",next_key,e->lock_ptr);
			if(next_key.lock_ptr != e->lock_ptr) {
				lookup_key1 = next_key;
				continue;//不是目标锁，跳过 
			}
			struct per_request per_request = {};
			err = bpf_map_lookup_elem(record_lock_fd,&next_key,&per_request);
			if (err < 0) {
				// printf(stderr, "failed to lookup info: %d\n", err);
				lookup_key1 = next_key;
				continue;//不是目标锁，跳过 
			}
			float wait_delay = (e->start_hold_time-per_request.start_request_time)/1000000000.0;
			if(wait_delay<=0||wait_delay>=10000)
				printf("%d(NULL)|",per_request.pid);
			else printf("%d(%ds)|",per_request.pid,((e->start_hold_time-per_request.start_request_time)/1000000000));
			lookup_key1 = next_key;
		}
	}else if(type == FUTEX_FLAG){
		printf("%-12s  0x%-8x  %-11s  %-11s  %-16llu  ",mfutex_type[e->type],e->lock_ptr,"NULL","NULL",e->start_hold_time);
		int err,futex_wake_queue_fd =bpf_map__fd(mfutex_skel->maps.futex_wake_queue);
		struct lock_record_key lookup_key1 = {-1,-1}, next_key;
		while(!bpf_map_get_next_key(futex_wake_queue_fd, &lookup_key1, &next_key)){
			// printf("next_key:%x target_ptr:%x\n",next_key,e->lock_ptr);
			if(next_key.lock_ptr != e->lock_ptr) {
				lookup_key1 = next_key;
				continue;//不是目标锁，跳过 
			}
			struct per_request per_request = {};
			err = bpf_map_lookup_elem(futex_wake_queue_fd,&next_key,&per_request);
			if (err < 0) {
				// printf(stderr, "failed to lookup info: %d\n", err);
				lookup_key1 = next_key;
				continue;//不是目标锁，跳过 
			}
			
			float wait_delay = (e->start_hold_time-per_request.start_request_time)/1000000000.0;
			if(wait_delay<=0||wait_delay>=10000)
				printf("%d(NULL)| ",per_request.pid);
			else printf("%d(%ds)| ",per_request.pid,((e->start_hold_time-per_request.start_request_time)/1000000000));
			err = bpf_map_delete_elem(futex_wake_queue_fd, &next_key);
			if (err < 0) {
				fprintf(stderr, "failed to cleanup infos: %d\n", err);
				return -1;
			}
			lookup_key1 = next_key;
		}
		printf("\n%-81s","");
		int err2,futex_wait_queue_fd =bpf_map__fd(mfutex_skel->maps.futex_wait_queue);
		struct lock_record_key lookup_key2 = {-1,-1};
		while(!bpf_map_get_next_key(futex_wait_queue_fd, &lookup_key2, &next_key)){
			// printf("next_key:%x target_ptr:%x\n",next_key,e->lock_ptr);
			if(next_key.lock_ptr != e->lock_ptr) {
				lookup_key2 = next_key;
				continue;//不是目标锁，跳过 
			}
			struct per_request per_request = {};
			err2 = bpf_map_lookup_elem(futex_wait_queue_fd,&next_key,&per_request);
			if (err2 < 0) {
				// printf(stderr2, "failed to lookup info: %d\n", err2);
				lookup_key2 = next_key;
				continue;//不是目标锁，跳过 
			}
			
			float wait_delay = (e->start_hold_time-per_request.start_request_time)/1000000000.0;
			if(wait_delay<=0||wait_delay>=10000)
				printf("%d(NULL)| ",per_request.pid);
			else printf("%d(%ds)| ",per_request.pid,((e->start_hold_time-per_request.start_request_time)/1000000000));
			lookup_key2 = next_key;
		}
		printf("\n");
	}
	printf("\n");
	// struct record_lock_key key;
	// key.lock_ptr = e->lock_ptr;
	// key.cnt = 1;
	// while(key.cnt<=e->cnt){
	// 	struct per_request per_request;
	// 	err = bpf_map_lookup_elem(record_lock_fd,&key,&per_request);
	// 	if (err < 0) {
	// 		// fprintf(stderr, "failed to lookup info: %d\n", err);
	// 		printf("(%llu|%d) ",key.lock_ptr,key.cnt);
	// 		key.cnt++;
	// 		continue;//没找到，就去找下一个
	// 	}
	// 	printf("%d(%lu)| ",per_request.pid,per_request.wait_delay);
	// 	key.cnt++;
	// }
	// printf("\n");
	return 0;
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void print_info1(const struct keytime_event *e)
{
	int i, args_counter = 0;

	for (i = 0; i < e->info_size && args_counter < e->info_count; i++) {
		char c = e->char_info[i];
		if (c == '\0') {
			args_counter++;
			putchar(' ');
		} else {
			putchar(c);
		}
	}
	if (e->info_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

static void print_info2(const struct keytime_event *e)
{
	int i=0;

	for(int tmp=e->info_count; tmp>0 ; tmp--){
		printf("%llu ",e->info[i++]);
	}
}

static void print_stack(unsigned long long address,FILE *file)
{
	const struct ksym *ksym;

	ksym = ksyms__map_addr(ksyms, address);
	if (ksym)
		fprintf(file, "0x%llx %s+0x%llx\n", address, ksym->name, address - ksym->addr);
	else
		fprintf(file, "0x%llx [unknown]\n", address);
}

static int print_keytime(void *ctx, void *data,unsigned long data_sz)
{
	const struct keytime_event *e = data;
	const struct offcpu_event *offcpu_event = data;
	bool is_offcpu = false;
	time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
	int kt_cur_tgid = 0;

	if(e->tgid != -1)	kt_cur_tgid = 2;
	else	kt_cur_tgid = 1;

	if(e->type == 11){
		is_offcpu = true;
	}
	
	if(prev_image != KEYTIME_IMAGE || env.kt_prev_tgid != kt_cur_tgid){
        printf("KEYTIME -------------------------------------------------------------------------------------------------\n");
        printf("%-8s  ","TIME");
		if(e->tgid != -1){
			printf("%-6s  ","TGID");
			env.kt_prev_tgid = 2;
		} else {
			env.kt_prev_tgid = 1;
		}
		printf("%-6s  %-15s  %s\n","PID","EVENT","ARGS/RET/OTHERS");

		prev_image = KEYTIME_IMAGE;
    }

	printf("%02d:%02d:%02d  ",hour,min,sec);
	if(e->tgid != -1)	printf("%-6d  ",e->tgid);
	if(!is_offcpu){
		printf("%-6d  %-15s  ",e->pid,keytime_type[e->type]);
		if(e->type==4 || e->type==5 || e->type==6 || e->type==7 || e->type==8 || e->type==9){
			printf("child_pid:");
		}
		if(e->type == 10){
			printf("oncpu_time:");
		}
		if(e->enable_char_info){
			print_info1(e);
		}else{
			print_info2(e);
		}
	}else{
		printf("%-6d  %-15s  offcpu_time:%llu",offcpu_event->pid,keytime_type[offcpu_event->type],offcpu_event->offcpu_time);
		// 将进程下CPU时的调用栈信息写入 .output/offcpu_stack.txt 中（包括时分秒时间、offcpu_time、pid、tgid、调用栈）
		// 每写入100次清空一次然后重写
		int count = offcpu_event->kstack_sz / sizeof(long long unsigned int);
		if(env.stack_count < 100){
			FILE *file = fopen("./.output/data/offcpu_stack.txt", "a");
			fprintf(file, "TIME:%02d:%02d:%02d  ", hour,min,sec);
			if(offcpu_event->tgid != -1)	fprintf(file, "TGID:%-6d  ",offcpu_event->tgid);
			fprintf(file, "PID:%-6d  OFFCPU_TIME:%llu\n",offcpu_event->pid,offcpu_event->offcpu_time);
			for(int i=0 ; i<count ; i++){
				print_stack(offcpu_event->kstack[i],file);
			}
			fprintf(file, "\n");
			fclose(file);
			env.stack_count++;
		}else{
			FILE *file = fopen("./.output/data/offcpu_stack.txt", "w");
			fprintf(file, "TIME:%02d:%02d:%02d  ", hour,min,sec);
			if(offcpu_event->tgid != -1)	fprintf(file, "TGID:%-6d  ",offcpu_event->tgid);
			fprintf(file, "PID:%-6d  OFFCPU_TIME:%llu\n",offcpu_event->pid,offcpu_event->offcpu_time);
			for(int i=0 ; i<count ; i++){
				print_stack(offcpu_event->kstack[i],file);
			}
			fprintf(file, "\n");
			fclose(file);
			env.stack_count = 1;
		}
	}

	putchar('\n');

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int lock_attach(struct lock_image_bpf *skel)
{
	int err;
	
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_rdlock,__pthread_rwlock_rdlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_rdlock,__pthread_rwlock_rdlock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_tryrdlock,__pthread_rwlock_tryrdlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_tryrdlock,__pthread_rwlock_tryrdlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_wrlock,__pthread_rwlock_wrlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_wrlock,__pthread_rwlock_wrlock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_trywrlock,__pthread_rwlock_trywrlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_trywrlock,__pthread_rwlock_trywrlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_unlock,__pthread_rwlock_unlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_unlock,__pthread_rwlock_unlock_exit);

	ATTACH_UPROBE_CHECKED(skel,pthread_spin_lock,pthread_spin_lock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_spin_lock,pthread_spin_lock_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_spin_trylock,pthread_spin_trylock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_spin_trylock,pthread_spin_trylock_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_spin_unlock,pthread_spin_unlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_spin_unlock,pthread_spin_unlock_exit);
	
	err = lock_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF lock skeleton");
	
	return 0;
}
static int mfutex_attach(struct mfutex_bpf *skel)
{
	int err;
	
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_exit);
	// ATTACH_UPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_enter);
	// ATTACH_URETPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_enter);
	
	// ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_exit);
	
	
	err = mfutex_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF mfutex skeleton");
	
	return 0;
}

static int keytime_attach(struct keytime_image_bpf *skel)
{
	int err;

	ATTACH_URETPROBE_CHECKED(skel,fork,fork_exit);
	ATTACH_URETPROBE_CHECKED(skel,vfork,vfork_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_create,pthread_create_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_create,pthread_create_exit);

	err = keytime_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF keytime skeleton");

	return 0;
}
// resourse和schedule每一秒收集一次数据
void *enable_function(void *arg) {
    env.create_thread = true;
    sleep(1);
    if(env.enable_resource)	env.output_resourse = true;
	if(env.enable_schedule)	env.output_schedule = true;
    env.create_thread = false;
    env.exit_thread = true;

    return NULL;
}

static void sig_handler(int signo)
{
	exiting = true;
}

void get_hostname() {
    char hostname[64];
    int result = gethostname(hostname, sizeof(hostname));
    if (result == 0) {
        strcpy(env.hostname,hostname); 
    } else {
        perror("gethostname");
    }
}

int main(int argc, char **argv)
{
	struct bpf_map *rsc_ctrl_map = NULL;
	struct ring_buffer *syscall_rb = NULL;
	struct bpf_map *sc_ctrl_map = NULL;
	struct ring_buffer *lock_rb = NULL;
	struct bpf_map *lock_ctrl_map = NULL;
	struct ring_buffer *keytime_rb = NULL;
	struct bpf_map *kt_ctrl_map = NULL;
	struct ring_buffer *sched_rb = NULL;
	struct bpf_map *sched_ctrl_map = NULL;
	struct ring_buffer *mfutex_rb = NULL;
	struct bpf_map *mfutex_ctrl_map = NULL;
	pthread_t thread_enable;
	int key = 0;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	
	env.ignore_tgid = getpid();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	//signal(SIGTERM, sig_handler);

	if(env.enable_resource){
		resource_skel = resource_image_bpf__open();
		if(!resource_skel) {
			fprintf(stderr, "Failed to open BPF resource skeleton\n");
			return 1;
		}

		resource_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = resource_image_bpf__load(resource_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF resource skeleton\n");
			goto cleanup;
		}

		err = common_pin_map(&rsc_ctrl_map,resource_skel->obj,"rsc_ctrl_map",rsc_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		rscmap_fd = bpf_map__fd(rsc_ctrl_map);
		struct rsc_ctrl init_value= {false,-1,-1,false,-1};
		err = bpf_map_update_elem(rscmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}

		err = resource_image_bpf__attach(resource_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF resource skeleton\n");
			goto cleanup;
		}
	}

	if(env.enable_syscall){
		syscall_skel = syscall_image_bpf__open();
		if(!syscall_skel) {
			fprintf(stderr, "Failed to open BPF syscall skeleton\n");
			return 1;
		}

		// syscall_skel->rodata->ignore_tgid = env.ignore_tgid;
		// get_hostname();
		// strcpy(syscall_skel->rodata->hostname,env.hostname);
		
		err = syscall_image_bpf__load(syscall_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF syscall skeleton\n");
			goto cleanup;
		}

		err = common_pin_map(&sc_ctrl_map,syscall_skel->obj,"sc_ctrl_map",sc_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		scmap_fd = bpf_map__fd(sc_ctrl_map);
		struct sc_ctrl init_value= {false,-1};
		err = bpf_map_update_elem(scmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}

		err = syscall_image_bpf__attach(syscall_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF syscall skeleton\n");
			goto cleanup;
		}

		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		syscall_rb = ring_buffer__new(bpf_map__fd(syscall_skel->maps.syscall_rb), print_syscall, NULL, NULL);
		if (!syscall_rb) {
			err = -1;
			fprintf(stderr, "Failed to create syscall ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_lock){
		lock_skel = lock_image_bpf__open();
		if (!lock_skel) {
			fprintf(stderr, "Failed to open BPF lock skeleton\n");
			return 1;
		}

		lock_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = lock_image_bpf__load(lock_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF lock skeleton\n");
			goto cleanup;
		}
		
		err = common_pin_map(&lock_ctrl_map,lock_skel->obj,"lock_ctrl_map",lock_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		lockmap_fd = bpf_map__fd(lock_ctrl_map);
		struct lock_ctrl init_value = {false,false,-1,-1};
		err = bpf_map_update_elem(lockmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}

		/* 附加跟踪点处理程序 */
		err = lock_attach(lock_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF lock skeleton\n");
			goto cleanup;
		}
		
		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		lock_rb = ring_buffer__new(bpf_map__fd(lock_skel->maps.lock_rb), print_lock, NULL, NULL);
		if (!lock_rb) {
			err = -1;
			fprintf(stderr, "Failed to create lock ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_mfutex){
		mfutex_skel = mfutex_bpf__open();
		if (!mfutex_skel) {
			fprintf(stderr, "Failed to open BPF mfutex skeleton\n");
			return 1;
		}

		mfutex_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = mfutex_bpf__load(mfutex_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF mfutex skeleton\n");
			goto cleanup;
		}
		
		err = common_pin_map(&mfutex_ctrl_map,mfutex_skel->obj,"mfutex_ctrl_map",mfutex_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		mfutexmap_fd = bpf_map__fd(mfutex_ctrl_map);
		struct mfutex_ctrl init_value = {false,false,-1,-1};
		err = bpf_map_update_elem(mfutexmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}

		/* 附加跟踪点处理程序 */
		err = mfutex_attach(mfutex_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF mfutex skeleton\n");
			goto cleanup;
		}
		
		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		mfutex_rb = ring_buffer__new(bpf_map__fd(mfutex_skel->maps.mfutex_rb), print_mfutex, NULL, NULL);
		if (!mfutex_rb) {
			err = -1;
			fprintf(stderr, "Failed to create mfutex ring buffer\n");
			goto cleanup;
		}
		printf("============================================ MFutex ============================================\n");
		printf("%-8s   %-12s  %-10s  %-11s  %-11s  %-16s  %-15s\n","TIME","LOCK_TYPE","LOCK_Addr","Last_Holder","Last_Delay","HoldTime","Waker/Waiter");
	}

	if(env.enable_keytime){
		keytime_skel = keytime_image_bpf__open();
		if (!keytime_skel) {
			fprintf(stderr, "Failed to open BPF keytime skeleton\n");
			return 1;
		}

		keytime_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = keytime_image_bpf__load(keytime_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF keytime skeleton\n");
			goto cleanup;
		}

		sched_ksyms = ksyms__load();
		if (!sched_ksyms) {
			fprintf(stderr, "failed to load kallsyms\n");
			goto cleanup;
		}

		err = common_pin_map(&kt_ctrl_map,keytime_skel->obj,"kt_ctrl_map",kt_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		ktmap_fd = bpf_map__fd(kt_ctrl_map);
		struct kt_ctrl init_value = {false,false,false,-1,-1};
		err = bpf_map_update_elem(ktmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}
		
		/* 附加跟踪点处理程序 */
		err = keytime_attach(keytime_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF keytime skeleton\n");
			goto cleanup;
		}
		
		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		keytime_rb = ring_buffer__new(bpf_map__fd(keytime_skel->maps.keytime_rb), print_keytime, NULL, NULL);
		if (!keytime_rb) {
			err = -1;
			fprintf(stderr, "Failed to create keytime ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_schedule){
		schedule_skel = schedule_image_bpf__open();
		if(!schedule_skel) {
			fprintf(stderr, "Failed to open BPF schedule skeleton\n");
			return 1;
		}

		bpf_map__set_value_size(schedule_skel->maps.stackmap,
					127 * sizeof(unsigned long));
		bpf_map__set_max_entries(schedule_skel->maps.stackmap, 1024);
	// if (!probe_tp_btf("sched_switch"))
		// bpf_program__set_autoload(schedule_skel->progs.sched_switch, false);
	// else
	// 	bpf_program__set_autoload(schedule_skel->progs.sched_switch_raw, false);

		err = schedule_image_bpf__load(schedule_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF schedule skeleton\n");
			goto cleanup;
		}
		// 用户态获得map
		err = common_pin_map(&sched_ctrl_map,schedule_skel->obj,"sched_ctrl_map",sched_ctrl_path);
		if(err < 0){
			goto cleanup;
		}
		schedmap_fd = bpf_map__fd(sched_ctrl_map);
		struct sched_ctrl init_value= {false,-1};
		err = bpf_map_update_elem(schedmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cleanup;
		}

		sched_ksyms = ksyms__load();
		if (!sched_ksyms) {
			fprintf(stderr, "failed to load kallsyms\n");
			goto cleanup;
		}
		sched_syms_cache = syms_cache__new(0);
		if (!sched_syms_cache) {
			fprintf(stderr, "failed to create syms_cache\n");
			goto cleanup;
		}
		err = schedule_image_bpf__attach(schedule_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF schedule skeleton\n");
			goto cleanup;
		}
		sched_rb = ring_buffer__new(bpf_map__fd(schedule_skel->maps.sched_rb), print_schedule, NULL, NULL);
		if (!sched_rb) {
			err = -1;
			fprintf(stderr, "Failed to create schedule ring buffer\n");
			goto cleanup;
		}
	}
	printf("1\n");
	/* 处理事件 */
	while (!exiting) {
		if(env.enable_resource || env.enable_schedule){
			// 等待新线程结束，回收资源
			if(env.exit_thread){
				env.exit_thread = false;
				if (pthread_join(thread_enable, NULL) != 0) {
					perror("pthread_join");
					exit(EXIT_FAILURE);
				}
			}

			// 创建新线程，设置 output
			if(!env.create_thread){
				printf("2\n");

				if (pthread_create(&thread_enable, NULL, enable_function, NULL) != 0) {
					perror("pthread_create");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(env.enable_resource && env.output_resourse){
			err = print_resource(resource_skel->maps.total,rscmap_fd);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
		}

		if(env.enable_syscall){
			err = ring_buffer__poll(syscall_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling syscall ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_lock){
			err = ring_buffer__poll(lock_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling lock ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_mfutex){
			err = ring_buffer__poll(mfutex_rb, 2000);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling mfutex ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_keytime){
			err = ring_buffer__poll(keytime_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling keytime ring buffer: %d\n", err);
				break;
			}
		}
		if(env.enable_schedule){
			err = ring_buffer__poll(sched_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling schedule ring buffer: %d\n", err);
				break;
			}
		}
		// if(env.enable_schedule && env.output_schedule){
		// 	// err = print_schedule(schedule_skel->maps.proc_schedule,schedule_skel->maps.target_schedule,
		// 	// 					 schedule_skel->maps.sys_schedule,schedmap_fd);
		// 	printf("3\n");

		// 	// print_offcpu_map();
		// 	// print_wakeup_map();
		// 	/* Ctrl-C will cause -EINTR */
		// 	// if (err == -EINTR) {
		// 	// 	err = 0;
		// 	// 	break;
		// 	// }
		// 	// if (err < 0) {
		// 	// 	break;
		// 	// }
		// }
	}

/* 卸载BPF程序 */
cleanup:
	if(env.enable_resource){
		bpf_map__unpin(rsc_ctrl_map, rsc_ctrl_path);
		resource_image_bpf__destroy(resource_skel);
	}
	if(env.enable_syscall){
		bpf_map__unpin(sc_ctrl_map, sc_ctrl_path);
		ring_buffer__free(syscall_rb);
		hashmap_free(map);
		syscall_image_bpf__destroy(syscall_skel);
	}
	if(env.enable_lock){
		bpf_map__unpin(lock_ctrl_map, lock_ctrl_path);
		ring_buffer__free(lock_rb);
		lock_image_bpf__destroy(lock_skel);
	}
	if(env.enable_mfutex){
		bpf_map__unpin(mfutex_ctrl_map, mfutex_ctrl_path);
		ring_buffer__free(mfutex_rb);
		mfutex_bpf__destroy(mfutex_skel);
	}
	if(env.enable_keytime){
		bpf_map__unpin(kt_ctrl_map, kt_ctrl_path);
		ksyms__free(ksyms);
		ring_buffer__free(keytime_rb);
		keytime_image_bpf__destroy(keytime_skel);
	}
	if(env.enable_schedule){
		bpf_map__unpin(sched_ctrl_map, sched_ctrl_path);
		ring_buffer__free(sched_rb);
		schedule_image_bpf__destroy(schedule_skel);
		syms_cache__free(sched_syms_cache);
		ksyms__free(sched_ksyms);
	}

	return err < 0 ? -err : 0;
}