#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>

void print_event(void *ctx, int cpu, void *data, __u32 size) {
    printf("get tc perf event\n");
}


int main() {
    const char* path = "/sys/fs/bpf/tc/globals/test_perf_array";
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        printf("failed to get pin table\n");
    }
    struct perf_buffer *pb = perf_buffer__new(fd, 8, &print_event, NULL, NULL, NULL);
    int err = libbpf_get_error(pb);
    if (err != 0) {
        printf("failed to create pb\n");
    }

    while (true) {
        perf_buffer__poll(pb, 1);
    }
    printf("test\n");
}
