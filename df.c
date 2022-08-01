#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

// The DumpsterFire memory allocator.

struct memheader {
    struct memheader *next_header;
    size_t size;
};

static void memheader_init(struct memheader *h, size_t size) {
    h->next_header = NULL;
    h->size = size;
}

struct memheader *heap;
size_t heap_size;

static void *create_heap(size_t pages) {
    size_t bytes = pages * sysconf(_SC_PAGESIZE);
    struct memheader *ptr = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    }
    heap = ptr;
    memheader_init(heap + 0, sizeof(struct memheader));
    memheader_init(heap + 1, bytes - sizeof(struct memheader));
    heap->next_header = heap + 1;
    heap_size = bytes;

    return (void *)ptr;
}

// TODO: Add an align: bool argument which aligns the addresses. (We also need to change memheader_init to align)
static void split_memheader(struct memheader *split, size_t sz) {
    assert(split->size > sz + sizeof(struct memheader));
    memheader_init(split + sz, split->size - sz);

    split->next_header = split + sz;
    split->size = sz;
}

struct alloc_spot {
    struct memheader *h;
    struct memheader *prev;
};

void alloc_spot_init(struct alloc_spot *spot, struct memheader *h,
                     struct memheader *prev) {
    spot->h = h;
    spot->prev = prev;
}

void alloc_spot_reserve(struct alloc_spot *spot) {
    spot->prev->next_header = spot->h->next_header;
}

static struct alloc_spot find_allocation_spot(const size_t n_bytes) {
    struct memheader *h = heap;
    struct memheader *prev = NULL;
    while (h != NULL) {
        // Found sufficient header
        if (h->size >= n_bytes) {
            fprintf(stderr, "Found sufficient header!\n");
            if (h->size > n_bytes + sizeof(struct memheader)) {
                fprintf(stderr, "Header is too big! Cropping...\n");
                // This header is too big; split it in two if we can fit an
                // extra header.
                split_memheader(h, n_bytes);
            }
            struct alloc_spot spot;
            alloc_spot_init(&spot, h, prev);
            return spot;
        }
        prev = h;
        h = h->next_header;
    }
    struct alloc_spot null;
    alloc_spot_init(&null, NULL, NULL);
    return null;
}

void *DF_allocate(const size_t n_bytes) {
    struct alloc_spot spot = find_allocation_spot(n_bytes);
    if (spot.h == NULL) {
        fprintf(stderr, "Failed to allocate\n");
        return NULL;
    }
    alloc_spot_reserve(&spot);
    return (void *)spot.h;
}

void DF_free(void *ptr, const size_t n_bytes) {
    memheader_init((struct memheader *)ptr, n_bytes);

    // TODO: Implement detection of freed blocks next to this one and MERGE.
    struct memheader *h = heap;
    while (h != NULL) {
        // Found list spot for ptr!
        if (ptr > (void *)h && ptr < (void *)h->next_header) {
            ((struct memheader *)ptr)->next_header = h->next_header;
            h->next_header = (struct memheader *)ptr;
            fprintf(stderr, "Successfully deallocated.\n");
            return;
        }
        h = h->next_header;
    }
    fprintf(stderr, "Couldn't deallocate!\n");
}

int main() {
    create_heap(3);
    char* ptrs[100];
    for (int i = 0; i < 100; i++) {
        char *str = DF_allocate(6 * sizeof(char));
        strcpy(str, "hello");
	ptrs[i] = str;
    }

    for (int i = 0; i < 100; i += 2) {
	DF_free(ptrs[i], 6 * sizeof(char));
    }

    for (int i = 0; i < 100; i += 2) {
	char* str = DF_allocate(4 * sizeof(char));
	strcpy(str, "abc");
	ptrs[i] = str;
    }

    // Full deallocation
    for (int i = 0; i < 100; i++) {
	DF_free(ptrs[i], ((i % 2 == 0) ? 4 : 6) * sizeof(char));
    }
}
