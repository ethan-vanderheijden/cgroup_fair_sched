#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile unsigned long long root_cgroup;  // can be 0 for no restriction
const volatile int total_cpus;

// FALLBACK_DSQ will simply be FIFO
#define FALLBACK_DSQ 0
// slice is 5ms
#define SLICE 5000000

struct cpumask_wrapper {
    struct bpf_cpumask __kptr *mask;
};

// this is initialized by whoever loads the eBPF
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, u32);
    __type(value, long);
    __uint(max_entries, 1);
} enabled SEC(".maps");

// identical to `enabled` array but in a more convenient form
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cpumask_wrapper);
    __uint(max_entries, 1);
} valid_cpus SEC(".maps");

// subset of `enabled` with only CPUs that are not assigned to a cgroup yet
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cpumask_wrapper);
    __uint(max_entries, 1);
} unallocated_cpus SEC(".maps");

struct cgv_node {
    struct bpf_rb_node rb_node;
    // manually dispatched foreign procs are pre-emptively charged for an entire timeslice
    // cgroup_ctx.delta_foreign_time is the (SLICE - actual running time) of foreign procs
    // so foreign_time - delta_foreign_time is the actual foreign time

    // Note: direct dispatched foreign procs are completely ignored
    // probably OK since direct dispatch only happens if there is no contention for foreign CPUs
    u64 foreign_time;
    u64 cgid;
};

u64 max_foreign_time;
private(CGV_TREE) struct bpf_spin_lock cgv_lock;
private(CGV_TREE) struct bpf_rb_root cgv_tree __contains(cgv_node, rb_node);

// CPUs that are currently running tasks not belonging to their assigned cgroup
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cpumask_wrapper);
    __uint(max_entries, 1);
} cpus_foreign_affinity SEC(".maps");

struct cgroup_ctx {
    // access is not racy since it is only mutated on cgroup init/exit
    struct bpf_cpumask __kptr *soft_pin;
    // stores max scx.dsq_vtime for any process in this cgroup that has run
    // difference between any task->scx.dsq_vtime is the lag time
    // Warning: make sure to reset lag time in task init and wakeup!
    u64 max_vtime;
};

struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct cgroup_ctx);
} cgroup_ctx_array SEC(".maps");

// info cgroups need to read from each other
// can't store it in cgroup_ctx since cgroup might be in another cgroup namespace
struct cgroup_public_ctx {
    // stores cgv_node if it isn't currently in the rbtree
    struct cgv_node __kptr *node_stash;
    // accumulates cgroup proc's foreign running time asynchronously (Warning: updated
    // concurrently!) subtract from cgv_node.foreign_time when possible
    s64 delta_foreign_time;
    u16 cpus_allocated;  // acts as the "effective weight" of the cgroup
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct cgroup_public_ctx);
} cgroup_public SEC(".maps");

struct cpu_ctx {
    // access to assigned_cgroup is racy, but that's OK
    // if a process is placed in the wrong queue, it will get fixed on the next dispatch
    u32 assigned_cgroup;  // 0 indicates no assigned cgroup
    bool foreign_dispatched;
    // temporary cpumask used in find_direct_dispatch()
    // but better to allocated once when CPU initializes than on every call
    struct bpf_cpumask __kptr *temp_mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct cpu_ctx);
    __uint(max_entries, 1);
} cpu_ctx_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u64);
} task_start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    /* [switch with local affinity, re-ran prev, direct dispatch, interrupted, dispatched foreign]
     */
    __uint(max_entries, 5);
} stats SEC(".maps");

static bool is_enabled(void) {
    u32 key = 0;
    bool *val = bpf_map_lookup_elem(&enabled, &key);
    if (!val) {
        return false;
    } else {
        return *val != 0;
    }
}

static struct cpu_ctx *get_cpu_ctx() {
    u32 key = 0;
    struct cpu_ctx *ctx = bpf_map_lookup_elem(&cpu_ctx_array, &key);
    if (ctx == NULL) {
        scx_bpf_error("Failed to get CPU context");
        return NULL;
    }
    return ctx;
}

static struct cgroup_ctx *get_cgroup_ctx(struct cgroup *cgrp) {
    return bpf_cgrp_storage_get(&cgroup_ctx_array, cgrp, NULL, 0);
}

#define GET_MAP(map)                                                 \
    u32 key = 0;                                                     \
    struct cpumask_wrapper *value = bpf_map_lookup_elem(&map, &key); \
    if (value == NULL) {                                             \
        scx_bpf_error("Failed to get " #map " cpumask");             \
        return NULL;                                                 \
    }                                                                \
    struct bpf_cpumask *mask = value->mask;                          \
    if (mask == NULL) {                                              \
        scx_bpf_error("No cpumask found for " #map " CPUs");         \
        return NULL;                                                 \
    }                                                                \
    return mask;

static struct bpf_cpumask *lock_unallocated_cpus(void) {
    bpf_rcu_read_lock();
    GET_MAP(unallocated_cpus);
}

static struct bpf_cpumask *get_valid_cpus(void) { GET_MAP(valid_cpus); }

static struct bpf_cpumask *get_cpu_affinity(void) { GET_MAP(cpus_foreign_affinity); }

static u64 *get_task_start_time(struct task_struct *p) {
    u64 *stats = bpf_task_storage_get(&task_start_time, p, 0, 0);
    if (stats == NULL) {
        scx_bpf_error("Failed to get task stats for task %d", p->pid);
        return NULL;
    }
    return stats;
}

static bool cgv_comparator(struct bpf_rb_node *a, const struct bpf_rb_node *b) {
    struct cgv_node *cgv_a = container_of(a, struct cgv_node, rb_node);
    struct cgv_node *cgv_b = container_of(b, struct cgv_node, rb_node);
    return cgv_a->foreign_time < cgv_b->foreign_time;
}

// cgroup has extra processes that might want to run on foreign CPUs
static void enqueue_cgroup(struct cgroup_public_ctx *cgrp_state, struct cgv_node *node) {
    s64 time_offset = __sync_lock_test_and_set(&cgrp_state->delta_foreign_time, 0);
    node->foreign_time -= time_offset;

    // budget of "SLICE" means cgroup can monopolize "cpus_allocated" foreign CPUs for 1 timeslice
    u64 max_budget = SLICE * 3;
    // cgroups may stay off the rbtree for a long time if their processes are idle
    // must cap lag time to a reasonable amount
    if (time_before(node->foreign_time, max_foreign_time - max_budget)) {
        node->foreign_time = max_foreign_time - max_budget;
    }

    bpf_rbtree_add(&cgv_tree, &node->rb_node, cgv_comparator);
}

static void stat_inc(u32 idx) {
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p) (*cnt_p)++;
}

static s32 find_direct_dispatch(struct cgroup *cgrp, bool *direct_dispatch, bool *must_interrupt) {
    *direct_dispatch = false;
    *must_interrupt = false;
    s32 cpu = -1;

    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx != NULL && cgrp_ctx->soft_pin != NULL) {
        struct bpf_cpumask *soft_pin = cgrp_ctx->soft_pin;
        s32 idle_affinity = scx_bpf_pick_idle_cpu((cpumask_t *)soft_pin, 0);
        if (idle_affinity >= 0) {
            stat_inc(2);
            *direct_dispatch = true;
            return idle_affinity;
        } else {
            struct cpu_ctx *curr_ctx = get_cpu_ctx();
            if (curr_ctx == NULL) {
                goto skip;
            }
            struct bpf_cpumask *should_interrupt = curr_ctx->temp_mask;
            if (should_interrupt == NULL) {
                goto skip;
            }
            struct bpf_cpumask *foreign_affinity = get_cpu_affinity();
            if (foreign_affinity == NULL) {
                goto skip;
            }

            bpf_cpumask_and(should_interrupt, (cpumask_t *)soft_pin, (cpumask_t *)foreign_affinity);
            if (!bpf_cpumask_empty((cpumask_t *)should_interrupt)) {
                s32 to_interrupt = scx_bpf_pick_any_cpu((cpumask_t *)should_interrupt, 0);
                if (to_interrupt >= 0) {
                    stat_inc(3);
                    *direct_dispatch = true;
                    *must_interrupt = true;
                    return to_interrupt;
                }
            }

        skip:

            cpu = scx_bpf_pick_any_cpu((cpumask_t *)soft_pin, 0);
        }
    }

    struct bpf_cpumask *valid_cpus = get_valid_cpus();
    if (valid_cpus != NULL) {
        s32 idle_foreign = scx_bpf_pick_idle_cpu((cpumask_t *)valid_cpus, 0);
        if (idle_foreign >= 0) {
            stat_inc(2);
            *direct_dispatch = true;
            return idle_foreign;
        }

        if (cpu == -1) {
            cpu = scx_bpf_pick_any_cpu((cpumask_t *)valid_cpus, 0);
        }
    }

    return cpu;
}

s32 BPF_STRUCT_OPS(cgroup_fair_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);

    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx != NULL) {
        // task has just woken up
        // cap lag time to 1 slice
        if (time_before(p->scx.dsq_vtime, cgrp_ctx->max_vtime - SLICE)) {
            p->scx.dsq_vtime = cgrp_ctx->max_vtime - SLICE;
        }
    }

    bool direct_dispatch = false;
    bool must_interrupt = false;
    s32 cpu = find_direct_dispatch(cgrp, &direct_dispatch, &must_interrupt);

    bpf_cgroup_release(cgrp);
    if (direct_dispatch) {
        u64 flags = 0;
        if (must_interrupt) {
            flags |= SCX_ENQ_PREEMPT;
        }
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE, flags);
    }
    return cpu;
}

void BPF_STRUCT_OPS(cgroup_fair_enqueue, struct task_struct *p, u64 enq_flags) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    if (!(enq_flags & SCX_ENQ_CPU_SELECTED)) {
        // select_cpu() was not called, try direct dispatch to idle CPU
        bool direct_dispatch = false;
        bool must_interrupt = false;
        s32 cpu = find_direct_dispatch(cgrp, &direct_dispatch, &must_interrupt);
        if (direct_dispatch) {
            if (must_interrupt) {
                enq_flags |= SCX_ENQ_PREEMPT;
            }
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SLICE, enq_flags);
            bpf_cgroup_release(cgrp);
            return;
        }
    }

    u64 id = cgrp->kn->id;
    struct cgroup_public_ctx *state = bpf_map_lookup_elem(&cgroup_public, &id);
    if (state == NULL) {
        scx_bpf_dsq_insert(p, FALLBACK_DSQ, SLICE, enq_flags);
    } else {
        scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, SLICE, p->scx.dsq_vtime, enq_flags);

        struct cgv_node *node = bpf_kptr_xchg(&state->node_stash, NULL);
        if (node) {
            bpf_spin_lock(&cgv_lock);
            enqueue_cgroup(state, node);
            bpf_spin_unlock(&cgv_lock);
        }
    }
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_fair_dispatch, s32 cpu, struct task_struct *prev) {
    if (!is_enabled()) {
        return;
    }

    struct cpu_ctx *curr_ctx = get_cpu_ctx();
    if (curr_ctx != NULL && curr_ctx->assigned_cgroup > 0) {
        if (scx_bpf_dsq_move_to_local(curr_ctx->assigned_cgroup)) {
            // successfully switched out `prev` with a local-affinity process
            stat_inc(0);
            return;
        } else if (prev != NULL) {
            struct bpf_cpumask *foreign_affinity = get_cpu_affinity();
            if (foreign_affinity != NULL &&
                !bpf_cpumask_test_cpu(cpu, (cpumask_t *)foreign_affinity)) {
                // `prev` is a local-affinity process, let it keep running
                stat_inc(1);
                return;
            }
        }
    }

    // prev cannot possibly be a local-affinity process, switch it with a foreign process
    // check FALLBACK_DSQ first to ensure it doesn't starve
    scx_bpf_dsq_move_to_local(FALLBACK_DSQ);

    // we know this loop will terminate early since we are slowly draining the rbtree
    // but the verifier needs an explicit bound
    bpf_repeat(1000) {
        bpf_spin_lock(&cgv_lock);
        struct bpf_rb_node *rb_node = bpf_rbtree_first(&cgv_tree);
        if (rb_node == NULL) {
            bpf_spin_unlock(&cgv_lock);
            // tree is empty
            break;
        }

        rb_node = bpf_rbtree_remove(&cgv_tree, rb_node);
        bpf_spin_unlock(&cgv_lock);

        if (rb_node == NULL) {
            scx_bpf_error("Failed to remove left node from cgv_tree");
            break;
        }

        struct cgv_node *cgv = container_of(rb_node, struct cgv_node, rb_node);

        u64 id = cgv->cgid;
        struct cgroup_public_ctx *state = bpf_map_lookup_elem(&cgroup_public, &id);
        if (state == NULL) {
            // cgroup was deleted but cgv_node was in the rbtree and hasn't been cleaned up yet
            bpf_obj_drop(cgv);
            continue;
        }

        // move might fail if local-affinity CPUs end up grabbing all the processes
        bool found_proc = scx_bpf_dsq_move_to_local(cgv->cgid);
        if (found_proc) {
            stat_inc(4);

            if (time_before(max_foreign_time, cgv->foreign_time)) {
                max_foreign_time = cgv->foreign_time;
            }

            cgv->foreign_time += SLICE / state->cpus_allocated;
            struct cpu_ctx *curr_ctx = get_cpu_ctx();
            if (curr_ctx != NULL) {
                curr_ctx->foreign_dispatched = true;
            }
        }

        if (scx_bpf_dsq_nr_queued(cgv->cgid) > 0) {
            bpf_spin_lock(&cgv_lock);
            enqueue_cgroup(state, cgv);
            bpf_spin_unlock(&cgv_lock);
        } else {
            struct cgv_node *old = bpf_kptr_xchg(&state->node_stash, cgv);
            if (old) {
                bpf_obj_drop(old);
            }
        }

        if (found_proc) {
            break;
        }
    }
}

void BPF_STRUCT_OPS(cgroup_fair_running, struct task_struct *p) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    struct cpu_ctx *curr_ctx = get_cpu_ctx();

    if (curr_ctx != NULL) {
        if (curr_ctx->assigned_cgroup > 0) {
            bool local_affinity = cgrp->kn->id == curr_ctx->assigned_cgroup;
            u32 curr_cpu = bpf_get_smp_processor_id();
            struct bpf_cpumask *foreign_affinity = get_cpu_affinity();
            if (foreign_affinity != NULL) {
                if (!local_affinity) {
                    bpf_cpumask_set_cpu(curr_cpu, foreign_affinity);
                } else {
                    bpf_cpumask_clear_cpu(curr_cpu, foreign_affinity);
                }
            }
        }
    }

    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx != NULL) {
        // updating max_vtime is racy! but let's just live with it
        if (time_before(cgrp_ctx->max_vtime, p->scx.dsq_vtime)) {
            cgrp_ctx->max_vtime = p->scx.dsq_vtime;
        }
    }

    u64 *start = get_task_start_time(p);
    if (start != NULL) {
        *start = scx_bpf_now();
    }

    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_fair_stopping, struct task_struct *p, bool runnable) {
    u64 *start = get_task_start_time(p);
    if (start != NULL) {
        u64 now = scx_bpf_now();
        u64 vtime = now - *start;
        p->scx.dsq_vtime += vtime;

        struct cgroup *cgrp = scx_bpf_task_cgroup(p);
        struct cpu_ctx *curr_ctx = get_cpu_ctx();
        if (curr_ctx != NULL) {
            if (curr_ctx->foreign_dispatched) {
                u64 id = cgrp->kn->id;
                struct cgroup_public_ctx *state = bpf_map_lookup_elem(&cgroup_public, &id);
                if (state != NULL) {
                    s64 delta = SLICE - (s64)vtime;
                    // eBPF doesn't support signed division
                    if (delta < 0) {
                        delta = -((u64)(-delta) / state->cpus_allocated);
                    } else {
                        delta = (u64)delta / state->cpus_allocated;
                    }
                    __sync_fetch_and_add(&state->delta_foreign_time, delta);
                }
            }
            curr_ctx->foreign_dispatched = false;
        }
        bpf_cgroup_release(cgrp);
    }
}

s32 BPF_STRUCT_OPS(cgroup_fair_init_task, struct task_struct *p, struct scx_init_task_args *args) {
    bpf_task_storage_get(&task_start_time, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(args->cgroup);
    if (cgrp_ctx != NULL) {
        p->scx.dsq_vtime = cgrp_ctx->max_vtime;
    }
    return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_cgroup_init, struct cgroup *cgrp,
                             struct scx_cgroup_init_args *args) {
    if (root_cgroup != 0) {
        struct cgroup *parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1);
        if (parent == NULL) {
            // we are initializing the root cgroup, skip it
            return 0;
        } else if (parent->kn->id != root_cgroup) {
            bpf_cgroup_release(parent);
            // we are initializing unrelated cgroup, skip it
            return 0;
        } else {
            bpf_cgroup_release(parent);
        }
    }

    s32 ret = 0;

    bpf_printk("Initializing child cgroup %llu", cgrp->kn->id);

    struct cgroup_ctx *state =
        bpf_cgrp_storage_get(&cgroup_ctx_array, cgrp, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (state == NULL) {
        scx_bpf_error("Failed to create cgroup state for %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto done;
    }

    int cpus_needed = div_round_up(args->weight, 100);
    if (scx_bpf_create_dsq(cgrp->kn->id, -1)) {
        scx_bpf_error("Failed to create dispatch queue for cgroup %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto done;
    }

    struct bpf_cpumask *cpumask = lock_unallocated_cpus();
    if (cpumask == NULL) {
        ret = -ENOENT;
        goto unlock;
    }

    if (bpf_cpumask_weight((cpumask_t *)cpumask) < cpus_needed) {
        scx_bpf_error("Not enough cpus available for new cgroup");
        ret = -ENOSPC;
        goto unlock;
    }

    struct bpf_cpumask *soft_pin = bpf_cpumask_create();
    if (soft_pin == NULL) {
        scx_bpf_error("Failed to allocate cpumask for new cgroup");
        ret = -ENOMEM;
        goto unlock;
    }

    bpf_printk("Allocated %d CPUs for cgroup %llu", cpus_needed, cgrp->kn->id);

    u32 key = 0;
    int i;
    bpf_for(i, 0, cpus_needed) {
        int i = bpf_cpumask_first((cpumask_t *)cpumask);
        bpf_cpumask_set_cpu(i, soft_pin);
        bpf_cpumask_clear_cpu(i, cpumask);

        struct cpu_ctx *ctx = bpf_map_lookup_percpu_elem(&cpu_ctx_array, &key, i);
        if (ctx != NULL) {
            ctx->assigned_cgroup = cgrp->kn->id;
        } else {
            scx_bpf_error("Failed to set assigned cgroup for CPU %d", i);
        }
    }
    struct bpf_cpumask *old_pin = bpf_kptr_xchg(&state->soft_pin, soft_pin);
    if (old_pin) {
        bpf_cpumask_release(old_pin);
    }

    u64 id = cgrp->kn->id;
    struct cgroup_public_ctx empty_state = {};
    if (bpf_map_update_elem(&cgroup_public, &id, &empty_state, BPF_NOEXIST)) {
        scx_bpf_error("Failed to create public cgroup context for %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto unlock;
    }

    struct cgroup_public_ctx *public_state = bpf_map_lookup_elem(&cgroup_public, &id);
    if (public_state == NULL) {
        scx_bpf_error("Failed to get public cgroup context for %llu", cgrp->kn->id);
        ret = -ENOENT;
        goto unlock;
    }

    struct cgv_node *node = bpf_obj_new(struct cgv_node);
    if (node == NULL) {
        scx_bpf_error("Failed to allocate cgv_node for cgroup %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto unlock;
    }

    node->foreign_time = max_foreign_time;
    node->cgid = cgrp->kn->id;

    public_state->cpus_allocated = cpus_needed;
    public_state->delta_foreign_time = 0;
    struct cgv_node *old = bpf_kptr_xchg(&public_state->node_stash, node);
    if (old) {
        bpf_obj_drop(old);
    }

unlock:
    bpf_rcu_read_unlock();

done:
    return ret;
}

void BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_cgroup_exit, struct cgroup *cgrp) {
    struct cgroup_ctx *state = get_cgroup_ctx(cgrp);
    if (state != NULL) {
        scx_bpf_destroy_dsq(cgrp->kn->id);
        struct bpf_cpumask *soft_pinning = bpf_kptr_xchg(&state->soft_pin, NULL);
        if (soft_pinning != NULL) {
            struct bpf_cpumask *unallocated_mask = lock_unallocated_cpus();
            if (unallocated_mask != NULL) {
                bpf_cpumask_or(unallocated_mask, (cpumask_t *)unallocated_mask,
                               (cpumask_t *)soft_pinning);
            }
            bpf_rcu_read_unlock();

            int i;
            bpf_for(i, 0, bpf_cpumask_weight((cpumask_t *)soft_pinning)) {
                u32 cpu = bpf_cpumask_first((cpumask_t *)soft_pinning);
                bpf_cpumask_clear_cpu(cpu, soft_pinning);

                u32 key = 0;
                struct cpu_ctx *ctx = bpf_map_lookup_percpu_elem(&cpu_ctx_array, &key, cpu);
                if (ctx != NULL) {
                    ctx->assigned_cgroup = 0;
                } else {
                    scx_bpf_error("Failed to clear assigned cgroup for CPU %d", cpu);
                }
            }
            bpf_cpumask_release(soft_pinning);
        }

        u64 id = cgrp->kn->id;
        bpf_map_delete_elem(&cgroup_public, &id);
    }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_init) {
    s32 ret = scx_bpf_create_dsq(FALLBACK_DSQ, -1);
    if (ret) {
        scx_bpf_error("Failed to create fallback dispatch queue");
        return ret;
    }

    struct bpf_cpumask *new_mask = bpf_cpumask_create();
    struct bpf_cpumask *new_mask2 = bpf_cpumask_create();
    struct bpf_cpumask *new_mask3 = bpf_cpumask_create();
    if (new_mask == NULL || new_mask2 == NULL || new_mask3 == NULL) {
        scx_bpf_error("Failed to allocate cpumasks for managed CPUs");
        if (new_mask) bpf_cpumask_release(new_mask);
        if (new_mask2) bpf_cpumask_release(new_mask2);
        if (new_mask3) bpf_cpumask_release(new_mask3);
        return -ENOMEM;
    }

    int key = 0;
    struct cpumask_wrapper *foreign_affinity = bpf_map_lookup_elem(&cpus_foreign_affinity, &key);
    if (foreign_affinity == NULL) {
        scx_bpf_error("Failed to get cpus with foreign affinity map");
        return -ENOENT;
    }
    struct bpf_cpumask *old_affinity = bpf_kptr_xchg(&foreign_affinity->mask, new_mask3);
    if (old_affinity) {
        bpf_cpumask_release(old_affinity);
    }

    for (int i = 0; i < total_cpus; i++) {
        u32 key = 0;
        bool *is_enabled = bpf_map_lookup_percpu_elem(&enabled, &key, i);
        if (is_enabled != NULL && *is_enabled) {
            bpf_cpumask_set_cpu(i, new_mask);

            struct cpu_ctx *cpu_context = bpf_map_lookup_percpu_elem(&cpu_ctx_array, &key, i);
            if (cpu_context == NULL) {
                scx_bpf_error("Failed to get CPU context for CPU %d", i);
                bpf_cpumask_release(new_mask);
                bpf_cpumask_release(new_mask2);
                return -ENOENT;
            }
            struct bpf_cpumask *temp_mask = bpf_cpumask_create();
            if (temp_mask == NULL) {
                scx_bpf_error("Failed to allocate temp_mask cpumask for CPU %d", i);
                bpf_cpumask_release(new_mask);
                bpf_cpumask_release(new_mask2);
                return -ENOMEM;
            }
            struct bpf_cpumask *old = bpf_kptr_xchg(&cpu_context->temp_mask, temp_mask);
            if (old != NULL) {
                bpf_cpumask_release(old);
            }
        }
    }
    bpf_cpumask_copy(new_mask2, (cpumask_t *)new_mask);

    bpf_printk("Total CPUs enabled: %d", bpf_cpumask_weight((cpumask_t *)new_mask));

    struct cpumask_wrapper *valid = bpf_map_lookup_elem(&valid_cpus, &key);
    if (valid == NULL) {
        scx_bpf_error("Failed to set global cpumask for valid CPUs");
        bpf_cpumask_release(new_mask);
        bpf_cpumask_release(new_mask2);
        return -ENOENT;
    }
    struct bpf_cpumask *old_valid = bpf_kptr_xchg(&valid->mask, new_mask);
    if (old_valid) {
        bpf_cpumask_release(old_valid);
    }

    struct cpumask_wrapper *unallocated = bpf_map_lookup_elem(&unallocated_cpus, &key);
    if (unallocated == NULL) {
        scx_bpf_error("Failed to set global cpumask for unallocated CPUs");
        bpf_cpumask_release(new_mask2);
        return -ENOENT;
    }

    struct bpf_cpumask *old_unallocated = bpf_kptr_xchg(&unallocated->mask, new_mask2);
    if (old_unallocated) {
        bpf_cpumask_release(old_unallocated);
    }

    return 0;
}

void BPF_STRUCT_OPS(cgroup_fair_exit, struct scx_exit_info *ei) { UEI_RECORD(uei, ei); }

SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {.select_cpu = (void *)cgroup_fair_select_cpu,
                                  .enqueue = (void *)cgroup_fair_enqueue,
                                  .dispatch = (void *)cgroup_fair_dispatch,
                                  .running = (void *)cgroup_fair_running,
                                  .stopping = (void *)cgroup_fair_stopping,
                                  .init_task = (void *)cgroup_fair_init_task,
                                  .cgroup_init = (void *)cgroup_fair_cgroup_init,
                                  .cgroup_exit = (void *)cgroup_fair_cgroup_exit,
                                  .init = (void *)cgroup_fair_init,
                                  .exit = (void *)cgroup_fair_exit,
                                  .flags = SCX_OPS_SWITCH_PARTIAL,
                                  .name = "cgroup_fair"};
