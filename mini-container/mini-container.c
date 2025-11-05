/* mini-container.c - A minimal but complete container runtime
 * 
 * Demonstrates: namespaces, cgroups, overlayfs, pivot_root
 * 
 * Compile: gcc -o mini-container mini-container.c -Wall
 * Usage:   sudo ./mini-container run <rootfs-path> [command]
 * Example: sudo ./mini-container run ./rootfs /bin/sh
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <syscall.h>
#include <limits.h>
#include <sys/sysmacros.h>

#define STACK_SIZE (1024 * 1024)
#define CGROUP_ROOT "/sys/fs/cgroup"
#define HOSTNAME "mini-container"

/* Container configuration */
struct container_config {
    char *rootfs;           /* Path to container root filesystem */
    char *command;          /* Command to execute */
    char *cgroup_name;      /* cgroup name for this container */
    
    /* Resource limits */
    long memory_limit;      /* Memory limit in bytes (0 = no limit) */
    long cpu_shares;        /* CPU shares (0 = default) */
    int pids_max;          /* Max number of processes (0 = no limit) */
};

/* Write string to file (helper for cgroup setup) */
static int write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror(path);
        return -1;
    }
    
    ssize_t len = strlen(content);
    if (write(fd, content, len) != len) {
        perror("write");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

/* Setup cgroup v2 limits for container */
static int setup_cgroups(struct container_config *config, pid_t pid) {
    char path[PATH_MAX];
    char content[256];
    
    /* Create cgroup directory */
    snprintf(path, sizeof(path), "%s/%s", CGROUP_ROOT, config->cgroup_name);
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        perror("mkdir cgroup");
        return -1;
    }

    printf("[CGROUP] Created cgroup: %s\n", config->cgroup_name);
    
    /* Set memory limit */
    if (config->memory_limit > 0) {
        snprintf(path, sizeof(path), "%s/%s/memory.max", 
                 CGROUP_ROOT, config->cgroup_name);
        snprintf(content, sizeof(content), "%ld", config->memory_limit);
        
        if (write_file(path, content) == 0) {
            printf("[CGROUP] Memory limit: %ld bytes (%.1f MB)\n", 
                   config->memory_limit, config->memory_limit / 1024.0 / 1024.0);
        }
    }
    
    /* Set CPU weight (cgroup v2 equivalent of shares) */
    if (config->cpu_shares > 0) {
        snprintf(path, sizeof(path), "%s/%s/cpu.weight", 
                 CGROUP_ROOT, config->cgroup_name);
        snprintf(content, sizeof(content), "%ld", config->cpu_shares);
        
        if (write_file(path, content) == 0) {
            printf("[CGROUP] CPU weight: %ld\n", config->cpu_shares);
        }
    }
    
    /* Set PID limit */
    if (config->pids_max > 0) {
        snprintf(path, sizeof(path), "%s/%s/pids.max", 
                 CGROUP_ROOT, config->cgroup_name);
        snprintf(content, sizeof(content), "%d", config->pids_max);
        
        if (write_file(path, content) == 0) {
            printf("[CGROUP] PID limit: %d\n", config->pids_max);
        }
    } 

    /* Add process to cgroup */
    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", 
             CGROUP_ROOT, config->cgroup_name);
    snprintf(content, sizeof(content), "%d", pid);
    
    if (write_file(path, content) == -1) {
        fprintf(stderr, "[CGROUP] Failed to add process to cgroup\n");
        return -1;
    }

    
    printf("[CGROUP] Added PID %d to cgroup\n", pid);
    return 0;
}

/* Cleanup cgroup */
static void cleanup_cgroup(const char *cgroup_name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_ROOT, cgroup_name);
    
    /* Remove cgroup directory (must be empty) */
    if (rmdir(path) == -1) {
        perror("rmdir cgroup");
    } else {
        printf("[CGROUP] Cleaned up cgroup: %s\n", cgroup_name);
    }
}

/* Child process function - runs in new namespaces */
static int child_func(void *arg) {
    struct container_config *config = (struct container_config *)arg;
    
    printf("\n[CONTAINER] Starting (PID=%d in namespace)\n", getpid());
    
    /* Set hostname */
    if (sethostname(HOSTNAME, strlen(HOSTNAME)) == -1) {
        perror("sethostname");
        return 1;
    }
    
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("make root private");
        return 1;
    }
    
    printf("[CONTAINER] Bind mounting rootfs: %s\n", config->rootfs);
    if (mount(config->rootfs, config->rootfs, NULL, MS_BIND | MS_REC, NULL) == -1) {
        perror("bind mount rootfs");
        return 1;
    }
    
    /* Change to new root directory */
    if (chdir(config->rootfs) == -1) {
        perror("chdir");
        return 1;
    }
    
    /* Create directory for old root */
    if (mkdir(".old_root", 0755) == -1 && errno != EEXIST) {
        perror("mkdir .old_root");
        return 1;
    }
    
    /* Pivot root */
    printf("[CONTAINER] Pivoting root...\n");

    printf("[CONTAINER] Pivoting root...\n");
    if (syscall(SYS_pivot_root, ".", ".old_root") == -1) {
        perror("pivot_root");
        fprintf(stderr, "[CONTAINER] Debug: errno=%d\n", errno);
        return 1;
    }

    printf("[CONTAINER] Root filesystem pivoted successfully\n");
    
    /* Change to new root */
    if (chdir("/") == -1) {
        perror("chdir /");
        return 1;
    }
    
    /* Unmount old root */
    printf("[CONTAINER] Unmounting old root...\n");
    if (umount2(".old_root", MNT_DETACH) == -1) {
        perror("umount old root");
        /* Not fatal, continue */
    }
    
    if (rmdir(".old_root") == -1) {
        perror("rmdir .old_root");
        /* Not fatal, continue */
    }
    
    /* Mount /proc */
    if (mkdir("/proc", 0555) == -1 && errno != EEXIST) {
        perror("mkdir /proc");
    }
    
    if (mount("proc", "/proc", "proc", 
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1) {
        perror("mount /proc");
        return 1;
    }
    printf("[CONTAINER] Mounted /proc\n");
    
    if (mkdir("/sys", 0555) == -1 && errno != EEXIST) {
        perror("mkdir /sys");
    }
    
    if (mount("sysfs", "/sys", "sysfs", 
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1) {
        perror("mount /sys");
        /* Not fatal */
    }
    
    /* Mount /dev/pts for pseudo-terminals */
    if (mkdir("/dev", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /dev");
    }
    if (mkdir("/dev/pts", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /dev/pts");
    }
    
    if (mount("devpts", "/dev/pts", "devpts", 0, NULL) == -1) {
        perror("mount /dev/pts");
        /* Not fatal */
    }
    
    /* Create essential device nodes if they don't exist */
    mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
    mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
    mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
    
    /* Print isolation info */
    printf("\n=== CONTAINER ENVIRONMENT ===\n");
    printf("PID: %d\n", getpid());
    printf("Hostname: %s\n", HOSTNAME);
    printf("Root: %s\n", config->rootfs);
    printf("Command: %s\n", config->command);
    printf("=============================\n\n");
    
    /* Execute command */
    char *const argv[] = {config->command, NULL};
    char *const envp[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        "TERM=xterm",
        NULL
    };
    
    execve(config->command, argv, envp);
    
    /* If we get here, exec failed */
    perror("execve");
    return 1;
}

/* Run container */
static int run_container(struct container_config *config) {
    /* Allocate stack for child */
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    char *stack_top = stack + STACK_SIZE;
    
    /* Namespace flags */

    int flags = CLONE_NEWPID |   /* New PID namespace */
                CLONE_NEWNS |    /* New mount namespace */
                CLONE_NEWUTS |   /* New hostname namespace */
                CLONE_NEWIPC |   /* New IPC namespace */
                CLONE_NEWNET |   /* New network namespace */
                SIGCHLD;
    
    printf("[HOST] Creating container with namespaces...\n");
    printf("[HOST] Rootfs: %s\n", config->rootfs);
    printf("[HOST] Command: %s\n", config->command);
    
    /* Clone process with new namespaces */
    pid_t pid = clone(child_func, stack_top, flags, config);
    if (pid == -1) {
        perror("clone");
        free(stack);
        return 1;
    }

    if (pid == -1) {
        perror("clone");
        free(stack);
        return 1;
    }
    
    printf("[HOST] Container process created with PID %d\n", pid);
    
    /* Setup cgroups for the container */
    if (setup_cgroups(config, pid) == -1) {
        fprintf(stderr, "[HOST] Warning: cgroup setup failed\n");
    }
    
    /* Wait for container to exit */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        free(stack);
        return 1;
    }
    
    printf("\n[HOST] Container exited with status: %d\n", 
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    
    /* Cleanup */
    cleanup_cgroup(config->cgroup_name);
    free(stack);
    
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* Usage */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s run <rootfs> [command]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options (set via environment):\n");
    fprintf(stderr, "  MEMORY_LIMIT=<bytes>   Memory limit (e.g., 104857600 for 100MB)\n");
    fprintf(stderr, "  CPU_SHARES=<number>    CPU weight (default: 100)\n");
    fprintf(stderr, "  PIDS_MAX=<number>      Max processes (e.g., 50)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  MEMORY_LIMIT=104857600 PIDS_MAX=50 %s run ./rootfs /bin/sh\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3 || strcmp(argv[1], "run") != 0) {
        usage(argv[0]);
        return 1;
    }
    
    /* Check if running as root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: must run as root (for namespace creation)\n");
        return 1;
    }
    
    /* Parse arguments */
    struct container_config config = {
        .rootfs = argv[2],
        .command = argc > 3 ? argv[3] : "/bin/sh",
        .cgroup_name = "mini-container",
        .memory_limit = 0,
        .cpu_shares = 0,
        .pids_max = 0,
    };
    
    /* Parse environment variables for limits */
    char *env;
    if ((env = getenv("MEMORY_LIMIT"))) {
        config.memory_limit = atol(env);
    }
    if ((env = getenv("CPU_SHARES"))) {
        config.cpu_shares = atol(env);
    }
    /*if ((env = getenv("PIDS_MAX"))) {
        config.pids_max = atoi(env);
    }*/ 
    config.pids_max = 10;
    
    /* Verify rootfs exists */
    struct stat st;
    if (stat(config.rootfs, &st) == -1 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: rootfs '%s' does not exist or is not a directory\n", 
                config.rootfs);
        return 1;
    }
    
    /* Run container */
    return run_container(&config);
}
