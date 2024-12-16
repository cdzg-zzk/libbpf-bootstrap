#ifndef __PROC_IMAGE_H
#define __PROC_IMAGE_H


#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

typedef long long unsigned int u64;
typedef unsigned int u32;


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

struct sc_ctrl {
    bool sc_func;
    pid_t target_pid;
};

// schedule_image
struct sched_ctrl {
    bool sched_func;
    pid_t target_pid;
};

#define TASK_COMM_LEN		16

// size 40
struct offcpu_val_t {
	// __u32 pid;
	__u32 tgid;
	int user_stack_id;
	int kern_stack_id;
	// __u64 delta;
	// __u64 offcpu_start;
	int state;
	int cpu;
	int next_pid;
	char next_comm[TASK_COMM_LEN];
};

// struct offcpu_val_t {
// 	__u64 delta;
// 	int state;
// 	int cpu;
// 	char comm[TASK_COMM_LEN];
// };

// size 28
struct wakeup_value_t {
	int waker_pid;
	int wakeup_kern_stack_id;
	int wakeup_user_stack_id;
	int cpu;
	int tgid;
	char waker_proc_comm[TASK_COMM_LEN];
	// int delta;
};

enum timestamp_type {
	OFFCPU = 0,
	ONCPU,
	WAKEUP,
	WAKEUPNEW,
	SWITCH,
	// SYSCALL,
};
enum interrup_type {
	SYSCALL = 0,
	SOFTIRQ = 1,
	HARDIRQ = 2,
	SIGNAL = 3,
};
struct timestamp_t {
	__u64 timestamp;
	enum timestamp_type ts_type; 
};
// interrupt
struct syscall_enter_t {
	int syscall_id;
	u64 timestamp;    
};
// size: 32
struct syscall_val_t {
	int syscall_id;
	int ret;
	u64 timestamp;  
	u64 duration;
};
// struct syscall_count_t {
// 	int counts;
// 	u64 syscall_cost_time;
// };

struct softirq_enter_t {
	unsigned int vec_nr;
	u64 timestamp;
};
// size: 24
struct softirq_val_t {
	int dummy[2];
	unsigned int vec_nr;
	u64 timestamp;   
	u64 duration;
};

struct hardirq_enter_t {
	unsigned int irq;
	u64 timestamp;
};
// size: 56
struct hardirq_val_t {
	unsigned int irq;
	u64 timestamp; 
	u64 duration;
	char hardirq_name[32];
};
// size: 40
struct signal_handle_val_t {
	// enum interrup_type type;
	int sig;
	int dummy[4];
	u64 timestamp;
	u64 duration;
};
// size: 16
struct signal_val_t {
	// enum interrup_type type;
	int sig;
	u64 timestamp;
};
#endif /* __PROCESS_H */