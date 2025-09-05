#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"
#include "cgroup_fair.bpf.skel.h"
#include "user_exit_info.h"

const char help_fmt[] =
    "A cgroup scheduler that uses soft reservations. CPU weight / 100 is taken as the number of "
    "CPUs that the cgroup should be gaurenteed access to.\n"
    "\n"
    "Usage: %s [-f] [-c CPUs] [-r cgroup] [-v]\n"
    "  -r            Only apply soft reservations to children of this parent cgroup. By default, "
    "use root cgroup.\n"
    "  -c            Restrict scheduling to a subset of CPUs, e.g. \"2-4,7,9\"\n"
    "  -v            Enable verbose output\n"
    "  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

struct file_handle *_;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !verbose) return 0;
    return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple) { exit_req = 1; }

static void read_stats(struct cgroup_fair_bpf *skel, __u64 *stats) {
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 cnts[5][nr_cpus];
    __u32 idx;

    memset(stats, 0, sizeof(stats[0]) * 5);

    for (idx = 0; idx < 5; idx++) {
        int ret, cpu;

        ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts[idx]);
        if (ret < 0) continue;
        for (cpu = 0; cpu < nr_cpus; cpu++) stats[idx] += cnts[idx][cpu];
    }
}

unsigned long long get_cgroup_id(char *path) {
    int dirfd, err, flags, mount_id, fhsize;
    union {
        unsigned long long cgid;
        unsigned char raw_bytes[8];
    } id;
    char cgroup_workdir[512];
    struct file_handle *fhp, *fhp2;
    unsigned long long ret = 0;

    snprintf(cgroup_workdir, sizeof(cgroup_workdir), "/sys/fs/cgroup/%s", path);

    dirfd = AT_FDCWD;
    flags = 0;
    fhsize = sizeof(struct file_handle *);
    fhp = calloc(1, fhsize);
    if (!fhp) {
        return 0;
    }
    err = name_to_handle_at(dirfd, cgroup_workdir, fhp, &mount_id, flags);
    if (err >= 0 || fhp->handle_bytes != 8) {
        goto free_mem;
    }

    fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
    fhp2 = realloc(fhp, fhsize);
    if (!fhp2) {
        goto free_mem;
    }
    err = name_to_handle_at(dirfd, cgroup_workdir, fhp2, &mount_id, flags);
    fhp = fhp2;
    if (err < 0) {
        goto free_mem;
    }

    memcpy(id.raw_bytes, fhp->f_handle, 8);
    ret = id.cgid;

free_mem:
    free(fhp);
    return ret;
}

int main(int argc, char **argv) {
    struct cgroup_fair_bpf *skel;
    struct bpf_link *link;
    __u32 opt;

    int cpus = libbpf_num_possible_cpus();
    long *enabled_cpus = malloc(cpus * sizeof(long));
    memset(enabled_cpus, true, cpus * sizeof(long));

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    skel = cgroup_fair_bpf__open();

    char *cgroup = "";

    while ((opt = getopt(argc, argv, "vhr:c:")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            case 'c': {
                memset(enabled_cpus, false, cpus * sizeof(long));
                char *token = strtok(optarg, ",");
                while (token) {
                    char *dash = strchr(token, '-');
                    if (dash) {
                        *dash = '\0';
                        int start = atoi(token);
                        int end = atoi(dash + 1);
                        if (start < 0 || end >= cpus || start > end) {
                            fprintf(stderr, "Invalid CPU range: %s\n", optarg);
                            return 1;
                        }
                        for (int i = start; i <= end; i++) {
                            enabled_cpus[i] = true;
                        }
                    } else {
                        int cpu = atoi(token);
                        if (cpu < 0 || cpu >= cpus) {
                            fprintf(stderr, "Invalid CPU number: %d\n", cpu);
                            return 1;
                        }
                        enabled_cpus[cpu] = true;
                    }
                    token = strtok(NULL, ",");
                }
                break;
            }
            case 'r':
                cgroup = optarg;
                break;
            default:
                fprintf(stderr, help_fmt, basename(argv[0]));
                return opt != 'h';
        }
    }

    unsigned long long cgroup_id = get_cgroup_id(cgroup);
    if (cgroup_id == 0) {
        fprintf(stderr, "cgroup %s is invalid\n", cgroup);
        return 1;
    }
    skel->rodata->root_cgroup = cgroup_id;
    skel->rodata->total_cpus = cpus;

    UEI_SET_SIZE(skel, sched_ops, uei);
    if (cgroup_fair_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    int key = 0;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.enabled), &key, enabled_cpus, BPF_EXIST)) {
        fprintf(stderr, "Failed to update enabled CPUs map\n");
        cgroup_fair_bpf__destroy(skel);
        return 1;
    }

    link = bpf_map__attach_struct_ops(skel->maps.sched_ops);

    while (!exit_req && !UEI_EXITED(skel, uei)) {
        __u64 stats[5];

        read_stats(skel, stats);
        printf(
            "switch: %llu, re-ran: %llu, direct-dispatch: %llu, interrupted: %llu, foreign: %llu\n",
            stats[0], stats[1], stats[2], stats[3], stats[4]);
        fflush(stdout);
        sleep(1);
    }

    bpf_link__destroy(link);
    UEI_REPORT(skel, uei);
    cgroup_fair_bpf__destroy(skel);

    return 0;
}
