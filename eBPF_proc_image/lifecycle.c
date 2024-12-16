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
#include "comm.h"

#include "interrupt_trace.skel.h"
#include "schedule_trace.skel.h"

#include "hashmap.h"
#include "helpers.h"
#include "trace_helpers.h"
#include "syscall_helpers.h"

static volatile bool exiting = false;

static struct env {
	int self_tgid;
	bool enable_syscall;
	bool enable_schedule;
	int sc_prev_tgid;
} env = {
	.enable_syscall = false,
	.enable_schedule = false,
	.sc_prev_tgid = 0,
};


struct interrupt_trace_bpf *interrupt_skel = NULL;
struct schedule_trace_bpf *schedule_skel = NULL;

int schedule_fd;
int syscall_fd;

static int scmap_fd;
static int schedmap_fd;



static struct syms_cache *sched_syms_cache = NULL;
static struct ksyms *sched_ksyms = NULL;



#define GET_STATE_STR(state) 	strncpy(str, (state), 29); \
								break;

const char* get_task_state(int state) {
	static char str[30];
	switch (state)
	{
	case 0:
		GET_STATE_STR("TASK_RUNNING")
	case 1:
		GET_STATE_STR("TASK_INTERRUPTIBLE")
	case 2:
		GET_STATE_STR("TASK_UNINTERRUPTIBLE")
	case 4:
		GET_STATE_STR("__TASK_STOPPED")
	case 8:
		GET_STATE_STR("__TASK_TRACED")
	case 0x80:
		GET_STATE_STR("TASK_DEAD")
	case 0x200:
		GET_STATE_STR("TASK_WAKING")
	case 0x800:
		GET_STATE_STR("TASK_NEW")
	case 0x100:
		GET_STATE_STR("TASK_WAKEKILL")
	case 0x102:
		GET_STATE_STR("TASK_KILLABLE")
	case 0x402:
		GET_STATE_STR("TASK_IDLE")
	case 0x3:
		GET_STATE_STR("TASK_NORMAL")
	default:
		GET_STATE_STR("unknow_state")
		break;
	}
	printf("get state str: %s\n", str);
	return str;
}
char *timestamp_state[] = {"OFFCPU", "ONCPU", "WAKEUP", "WAKEUPNEW", "SWITCH", "SYSCALL"};


const char argp_program_doc[] ="Trace the lifecycle of  target process to get process key information.\n";

static const struct argp_option opts[] = {
	{ "all", 'a', NULL, 0, "Attach all eBPF functions(but do not start)" },
	{ "syscall", 's', NULL, 0, "Attach eBPF functions about syscall sequence(but do not start)" },
	{ "schedule", 'S', NULL, 0, "Attach eBPF functions about schedule (but do not start)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'a':
				env.enable_syscall = true;
				env.enable_schedule = true;
				break;
		case 's':
				env.enable_syscall = true;
                break;
		case 'S':
				env.enable_schedule = true;
				break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
        default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}


static void print_all_stack(int out_fd, int stack_fd, int kern_stack_id, int user_stack_id, int tgid, struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	ssize_t written_bytes = 0;
	char str[256];
	unsigned long *ip = calloc(127, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	int idx = 0;

	if (bpf_map_lookup_elem(stack_fd, &kern_stack_id, ip) != 0) {
		goto print_ustack;
	}

	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;

	for (int i = 0; i < 127 && ip[i]; i++) {
		ksym = ksyms__map_addr(ksyms, ip[i]);
		written_bytes = sprintf(str, "    #%-2d  %s\n",idx++, ksym ? ksym->name : "unknown"); 
		if(write(out_fd, str, written_bytes) != written_bytes) {
			fprintf(stderr, "Failed to write event str\n");
			continue;
		}
	}
print_ustack:
		if (user_stack_id == -1)
			goto cleanup;

		if (bpf_map_lookup_elem(stack_fd, &user_stack_id, ip) != 0) {
			goto cleanup;
		}
		struct sym_info sinfo;
		int err = 0;
		syms = syms_cache__get_syms(syms_cache, tgid);
		if (!syms) {
			goto cleanup;
		}
		for (int i = 0; i < 127 && ip[i]; i++) {
			err = syms__map_addr_dso(syms, ip[i], &sinfo);
			if (err == 0) {
				if (sinfo.sym_name) {
					written_bytes = sprintf(str, "    #%-2d %s",idx++, sinfo.sym_name); 
					if(write(out_fd, str, written_bytes) != written_bytes) {
						fprintf(stderr, "Failed to write event str\n");
						continue;
					}
				}
				written_bytes = sprintf(str, " (%s)", sinfo.dso_name); 
				if(write(out_fd, str, written_bytes) != written_bytes) {
					fprintf(stderr, "Failed to write event str\n");
					continue;
				}
			}
			write(out_fd, "\n", 1);
		}
cleanup:
	free(ip);
	return;
}

int print_offcpu_event(int out_fd, struct offcpu_val_t *offcpu_val, struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	int stack_fd = bpf_map__fd(schedule_skel->maps.stackmap);
	print_all_stack(out_fd, stack_fd, offcpu_val->kern_stack_id, offcpu_val->user_stack_id, offcpu_val->tgid, ksyms, syms_cache);
	char str[256];

	ssize_t written_bytes = sprintf(str, "CPU: %-2d  state: %s  switch to [%s]  next pid: %d\n", offcpu_val->cpu, get_task_state(offcpu_val->state), offcpu_val->next_comm, offcpu_val->next_pid); 
	if(write(out_fd, str, written_bytes) != written_bytes) {
		fprintf(stderr, "Failed to write event str\n");
	}
    return 0;
}
int print_wakeup_event(int out_fd, struct wakeup_value_t *wakeup_val, struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	int stack_fd = bpf_map__fd(schedule_skel->maps.stackmap);
	print_all_stack(out_fd, stack_fd, wakeup_val->wakeup_kern_stack_id, wakeup_val->wakeup_user_stack_id, wakeup_val->tgid, ksyms, syms_cache);
	char str[256];
	ssize_t written_bytes = sprintf(str, "CPU: %-2d  [%s] pid: %d  wake up target proc\n", wakeup_val->cpu, wakeup_val->waker_proc_comm, wakeup_val->waker_pid); 
	if(write(out_fd, str, written_bytes) != written_bytes) {
		fprintf(stderr, "Failed to write event str\n");
	}
    return 0;
}
static int print_schedule(void *ctx, void *data,unsigned long data_sz)
{
	switch(data_sz)
	{
		case sizeof(struct offcpu_val_t):
			struct offcpu_val_t *offcpu_val = (struct offcpu_val_t*)data;
			if(print_offcpu_event(schedule_fd, offcpu_val, sched_ksyms, sched_syms_cache)) {
				fprintf(stderr, "print offcpu event error\n");
			}
			break;
		case sizeof(struct wakeup_value_t):
			struct wakeup_value_t *wakeup_val = (struct wakeup_value_t*)data;
			if(print_wakeup_event(schedule_fd, wakeup_val, sched_ksyms, sched_syms_cache)) {
				fprintf(stderr, "print wakeup event error\n");
			}
			break;		
		case sizeof(struct timestamp_t):
			struct timestamp_t *timestamp_val = (struct timestamp_t*)data;
			char timestamp_str[256];
			int timestamp_bytes = sprintf(timestamp_str, "timestamp: %llu  [%s]  data size: %ld\n", timestamp_val->timestamp, timestamp_state[timestamp_val->ts_type], data_sz);
			if(write(schedule_fd, timestamp_str, timestamp_bytes) != timestamp_bytes) {
				fprintf(stderr, "Failed to write timestamp str\n");
			}
			break;
	}
	
	return 0;
}

#define GET_SYSCALL_NAME (syscall_val->syscall_id<syscall_names_size?syscall_names[syscall_val->syscall_id]:"[Unknow syscall]")
#define GET_SOFTIRQ_NAME (soft_val->vec_nr<NR_SOFTIRQS?vec_names[soft_val->vec_nr]:"[Unknow softirq]")
#define GET_SIGNAL_NAME(sig) (((sig) < ARRAY_SIZE(sig_name)) ? sig_name[(sig)] : "[Extened signal]")
static int print_syscall(void *ctx, void *data,unsigned long data_sz)
{
	int written_bytes = 0;
	switch(data_sz)
	{
		case sizeof(struct syscall_val_t):
			struct syscall_val_t* syscall_val = (struct syscall_val_t*)data;
			char syscall_str[256];
			written_bytes = sprintf(syscall_str, "data size: %ld  timestamp: %llu  [syscall]: %s   duration: %llu  ret: %d\n", data_sz, syscall_val->timestamp, GET_SYSCALL_NAME, syscall_val->duration, syscall_val->ret);
			if(write(syscall_fd, syscall_str, written_bytes) != written_bytes) {
				fprintf(stderr, "Failed to write syscall str\n");
			}
			break;
		case sizeof(struct softirq_val_t):
			struct softirq_val_t* soft_val = (struct softirq_val_t*)data;
			char softirq_str[256];
			written_bytes = sprintf(softirq_str, "data size: %ld  timestamp: %llu  [softirq]: %s   duration: %llu\n", data_sz, soft_val->timestamp, GET_SOFTIRQ_NAME, soft_val->duration);
			if(write(syscall_fd, softirq_str, written_bytes) != written_bytes) {
				fprintf(stderr, "Failed to write softirq str\n");
			}
			break;
		case sizeof(struct hardirq_val_t):
			struct hardirq_val_t* hardirq_val = (struct hardirq_val_t*)data;
			char hardirq_str[256];
			written_bytes = sprintf(hardirq_str, "data size: %ld  timestamp: %llu  [hardirq]: %s    duration: %llu\n", data_sz, hardirq_val->timestamp, hardirq_val->hardirq_name, hardirq_val->duration);
			if(write(syscall_fd, hardirq_str, written_bytes) != written_bytes) {
				fprintf(stderr, "Failed to write hardirq str\n");
			}
			break;
		case sizeof(struct signal_handle_val_t):
			struct signal_handle_val_t *signal_handle_val = (struct signal_handle_val_t*)data;
			char signal_handle_str[256];
			written_bytes = sprintf(signal_handle_str, "data size: %ld  timestamp: %llu  [signal]: %s    duration: %llu\n", data_sz, signal_handle_val->timestamp, GET_SIGNAL_NAME(signal_handle_val->sig), signal_handle_val->duration);
			if(write(syscall_fd, signal_handle_str, written_bytes) != written_bytes) {
				fprintf(stderr, "Failed to write signal handle str\n");
			}
			break;
		case sizeof(struct signal_val_t):
			struct signal_val_t *signal_val = (struct signal_val_t*)data;
			char signal_str[256];
			written_bytes = sprintf(signal_str, "data size: %ld  timestamp: %llu  [signal]: %s\n", data_sz, signal_val->timestamp, GET_SIGNAL_NAME(signal_val->sig));
			if(write(syscall_fd, signal_str, written_bytes) != written_bytes) {
				fprintf(stderr, "Failed to write signal str\n");
			}
			break;
		default:
			break;
	}
	
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}



static void sig_handler(int signo)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *syscall_rb = NULL;
	struct bpf_map *sc_ctrl_map = NULL;
	struct ring_buffer *sched_rb = NULL;
	struct bpf_map *sched_ctrl_map = NULL;

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
	
	env.self_tgid = getpid();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	// signal(SIGTERM, sig_handler);



	if(env.enable_syscall){
		interrupt_skel = interrupt_trace_bpf__open();
		if(!interrupt_skel) {
			fprintf(stderr, "Failed to open BPF syscall skeleton\n");
			return 1;
		}
		
		err = interrupt_trace_bpf__load(interrupt_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF syscall skeleton\n");
			goto cleanup;
		}

		err = common_pin_map(&sc_ctrl_map,interrupt_skel->obj,"sc_ctrl_map",sc_ctrl_path);
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

		err = interrupt_trace_bpf__attach(interrupt_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF syscall skeleton\n");
			goto cleanup;
		}

		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		syscall_rb = ring_buffer__new(bpf_map__fd(interrupt_skel->maps.syscall_rb), print_syscall, NULL, NULL);
		if (!syscall_rb) {
			err = -1;
			fprintf(stderr, "Failed to create syscall ring buffer\n");
			goto cleanup;
		}
		syscall_fd = open(syscall_out_path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if(syscall_fd < 0) {
			err = -1;
			fprintf(stderr, "Failed to create syscall out file\n");
			goto cleanup;
		}
	}

	if(env.enable_schedule){
		printf("enter enable_sched\n");
		schedule_skel = schedule_trace_bpf__open();
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

		err = schedule_trace_bpf__load(schedule_skel);
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
		err = schedule_trace_bpf__attach(schedule_skel);
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
		schedule_fd = open(schedule_out_path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		printf("schedule fd: %d\n", schedule_fd);
		if(schedule_fd < 0) {
			err = -1;
			fprintf(stderr, "Failed to create schedule out file\n");
			goto cleanup;
		}
	}
	printf("1\n");
	/* 处理事件 */
	while (!exiting) {
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
	}

/* 卸载BPF程序 */
cleanup:
	if(env.enable_syscall){
		bpf_map__unpin(sc_ctrl_map, sc_ctrl_path);
		ring_buffer__free(syscall_rb);
		interrupt_trace_bpf__destroy(interrupt_skel);
		close(syscall_fd);
	}

	if(env.enable_schedule){
		bpf_map__unpin(sched_ctrl_map, sched_ctrl_path);
		ring_buffer__free(sched_rb);
		schedule_trace_bpf__destroy(schedule_skel);
		syms_cache__free(sched_syms_cache);
		ksyms__free(sched_ksyms);
		close(schedule_fd);
	}

	return err < 0 ? -err : 0;
}