#include <stdio.h>
#include <stdbool.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include "proc_image.h"
#include "hashmap.h"
#include "helpers.h"

static struct env {
    // 1代表activate；2代表deactivate；3代表finish
    int usemode;
    int pid;
    int time;
    int syscalls;
    bool enable_myproc;
	bool output_schedule;
    bool enable_syscall;
    bool enable_schedule;
}  env = {
    .usemode = 0,
    .pid = -1,
    .syscalls = 0,
	.enable_myproc = false,
	.output_schedule = false,
    .enable_syscall = false,
    .enable_schedule = false,
};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
    { "activate", 'a', NULL, 0, "Set startup policy of proc_image tool" },
    { "deactivate", 'd', NULL, 0, "Initialize to the original deactivated state" },
    { "finish", 'f', NULL, 0, "Finish to run eBPF tool" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
    { "myproc", 'm', NULL, 0, "Trace the process of the tool itself (not tracked by default)" },
    { "syscall", 's', NULL, 0, "Collects syscall sequence (1~50) information about processes(any 1~50 when deactivated)" },
    { "schedule", 'S', NULL, 0, "Collects schedule information about processes (trace tool process)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    long pid;

    switch (key) {
        case 'a':
            env.usemode = 1;
            break;
        case 'd':
            env.usemode = 2;
            break;
        case 'f':
            env.usemode = 3;
            break;
        case 'p':
				errno = 0;
				pid = strtol(arg, NULL, 10);
				if (errno || pid < 0) {
					warn("Invalid PID: %s\n", arg);
					// 调用argp_usage函数，用于打印用法信息并退出程序
					argp_usage(state);
				}
				env.pid = pid;
				break;
        case 'm':
				env.enable_myproc = true;
				break;
		case 't':
				env.time = strtol(arg, NULL, 10);
				if(env.time) alarm(env.time);
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

int deactivate_mode(){
    int err;
    if(env.enable_syscall){
        struct sc_ctrl sc_ctrl = {false,-1};
        err = update_sc_ctrl_map(sc_ctrl);
        if(err < 0) return err;
    }

    if(env.enable_schedule){
        struct sched_ctrl sched_ctrl = {false,-1};
        err = update_sched_ctrl_map(sched_ctrl);
        if(err < 0) return err;
    }

    return 0;
}

static void sig_handler(int signo)
{
	deactivate_mode();
}

int main(int argc, char **argv)
{
    int err;
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    signal(SIGALRM,sig_handler);
	signal(SIGINT,sig_handler);
	signal(SIGTERM,sig_handler);
    // update_xx_ctrl_map()可以优化
    if(env.usemode == 1){                   // activate mode
        if(env.enable_syscall){
            printf("syscall\n");
            struct sc_ctrl sc_ctrl = {true,env.pid};
            err = update_sc_ctrl_map(sc_ctrl);
            if(err < 0) return err;
        }

        if(env.enable_schedule){
            printf("schedule\n");
            struct sched_ctrl sched_ctrl = {true,env.pid};
            err = update_sched_ctrl_map(sched_ctrl);
            if(err < 0) return err;
        }

        if(env.time!=0) pause();
    }else if(env.usemode == 2){             // deactivate mode
        err = deactivate_mode();
        if(err<0){
            fprintf(stderr, "Failed to deactivate\n");
            return err;
        }
    }else if(env.usemode == 3){             // finish mode
        const char *command = "pkill proc_image";
        int status = system(command);
        if (status == -1) {
            perror("system");
        }
    }else{
        // 输出help信息
        printf("Please enter the usage mode(activate/deactivate/finish) before selecting the function\n");
        argp_help(&argp, stderr, ARGP_HELP_LONG, argv[0]);
    }

    return 0;
}