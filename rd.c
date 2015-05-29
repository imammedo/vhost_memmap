#include "vhost_memmap.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

struct vhost_memory {
        uint32_t nregions;
        uint32_t padding;
        struct vhost_memory_region regions[0];
};

struct vhost_memory_region *find_region(struct vhost_memory *mem,
                                                     unsigned long long addr, uint32_t len)
{
        struct vhost_memory_region *reg;
        int i;

        for (i = 0; i < mem->nregions; ++i) {
                reg = mem->regions + i;
                if (reg->guest_phys_addr <= addr &&
                    reg->guest_phys_addr + reg->memory_size - 1 >= addr)
                        return reg;
        }
        return NULL;
}

void test_lookup(memmap_trie *map, struct vhost_memory *mem, vhost_memory_region *vm, int vm_count, unsigned long long step)
{
	int i;
	
	step = step ? step : 1;
	for (i = 0; i < vm_count; i++) {
		unsigned long long addr, end;

		end = vm[i].guest_phys_addr + vm[i].memory_size;
		for (addr = vm[i].guest_phys_addr; addr < end && addr >= vm[i].guest_phys_addr; addr += step) {
			if (!lookup_region(*(unsigned long long *)&map->root, addr)) {
				printf("Lookup addr: %.16llx\n", addr);
//				dump_map(map, &map->root);
				assert(0);
			};
			assert(find_region(mem, addr, 0));
		}
	}
}

void test_vhost_memory_array(char *name, vhost_memory_region *vm, int vm_count, unsigned long long step)
{
	int i;
	struct vhost_memory *mem;
	memmap_trie *map = vhost_create_memmap_trie();

	printf("\n\ntest_vhost_memory_array: %s\n\n", name);
	for (i = 0; i < vm_count; i++) {
		unsigned long long j, end;
		assert((vm[i].guest_phys_addr + vm[i].memory_size) > vm[i].guest_phys_addr);
		assert(vhost_insert_region(map, &vm[i]));
	}

	mem = malloc(sizeof(struct vhost_memory) + sizeof *vm * vm_count);
	memcpy(mem->regions, vm, sizeof *vm * vm_count);
	mem->nregions = vm_count;

//        dump_map(map, &map->root);
        test_lookup(map, mem, vm, vm_count, step);
	test_region_foreach(&map->root, vm, vm_count);
	free(mem);
	vhost_free_memmap_trie(map);
}

vhost_memory_region mixed[] = {
{ 0xaabb020000000001, 0x10000, 0x7fe3b0000000 },
{ 0xaabb021000000002, 0x10000, 0x7fe3b0000000 },
{ 0x0000000000000001, 0x10000, 0x7fe3b0000000 },
{ 0xaabb010000000003, 0x10000, 0x7fe3b0000000 },
{ 0xaabb020300000004, 0x10, 0x7fe3b0000000 },
{ 0xaabb020300000015, 0x10000, 0x7fe3b0000000 },
{ 0xaabb02103000cc05, 0x1, 0x7fe3b0000000 },
{ 0xaabb02103000cc06, 0x10000, 0x7fe3b0000000 },
{ 0xaabb011000000006, 0x10000, 0x7fe3b0000000 },
{ 0xaabb041000000007, 0x10000, 0x7fe3b0000000 },
{ 0x00000000dd000000, 0x10000, 0x7fe3b0000000 },
};

vhost_memory_region kvm_def[] = {
{ 0x000000000, 0xa0000, 0x7fe2f0000000 },
{ 0x200000000, 0x40000000, 0x7fe3b0000000 },
{ 0x400000000, 0x40000000, 0x7fe3b0000000 },
{ 0x0000c0000, 0x00100000, 0x7fe2f00c0000 },
{ 0x0fffc0000, 0x2000, 0x7fe3fdc00000 },
{ 0x100000000, 0x10000, 0x7fe3b0000000 },
{ 0x0f8000000, 0x4000000, 0x7fe2e8000000 },
{ 0x0fc054000, 0x2000, 0x7fe3fd600000 }
};

vhost_memory_region level_compression[] = {
{ 0x0000000000000000, 0x100, 0x7fe3b0000000 },
{ 0x0000000000100000, 0x1, 0x7fe3b0000000 },
};

vhost_memory_region iterator1[] = {
{ 0xff00000000000000, 0x100, 0x7fe3b0000000 },
};

vhost_memory_region iterator2[] = {
{ 0xff00000000000000, 0x100, 0x7fe3b0000000 },
{ 0xff00010000000000, 0x100, 0x7fe3b0000000 },
{ 0xffff000000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffaa0000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100200, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100300, 0x1, 0x7fe3b0000000 },
{ 0xffffff0000100301, 0xfe, 0x7fe3b0000000 },
};

vhost_memory_region iterator3[] = {
{ 0xff00000000000000, 0x1, 0x7fe3b0000000 },
{ 0xfffa000000000000, 0x5f00000000000, 0x7fe3b0000000 },
};

vhost_memory_region iterator4[] = {
{ 0xff00000000000000, 0x1, 0x7fe3b0000000 },
{ 0xfffa000000000000, 0x5ffffffffff00, 0x7fe3b0000000 },
};

vhost_memory_region split_leaf[] = {
{ 0xff00000000000000, 0x3, 0x7fe3b0000000 },
{ 0xfffa000000000000, 0x5f00000000000, 0x7fe3b0000000 },
{ 0xffffffffffffff00, 0x1, 0x7fe3b0000000 },
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define TEST_ARGS(var) #var, var, ARRAY_SIZE(var)
int main(int argc, char **argv)
{
	test_vhost_memory_array(TEST_ARGS(mixed), 1);
	test_vhost_memory_array(TEST_ARGS(kvm_def), 0x1000);
	test_vhost_memory_array(TEST_ARGS(level_compression), 0xfe);
	test_vhost_memory_array(TEST_ARGS(iterator1), 0x1);
	test_vhost_memory_array(TEST_ARGS(iterator2), 0x1);
	test_vhost_memory_array(TEST_ARGS(iterator3), 0x100000000);
	test_vhost_memory_array(TEST_ARGS(iterator4), 0x100000000);
	test_vhost_memory_array(TEST_ARGS(split_leaf), 0x100000000);
	return 0;
}
