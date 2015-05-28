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
		for (addr = vm[i].guest_phys_addr; addr < end; addr += step) {
		if (!lookup_region(*(unsigned long long *)&map->root, addr)) {
				//dump_map(map, &map->root);
				printf("addr: %.16llx\n", addr);
				assert(0);
			};
			assert(find_region(mem, addr, 0));
		}
	}
}

void test_vhost_memory_array(vhost_memory_region *vm, int vm_count, unsigned long long step)
{
	int i;
	struct vhost_memory *mem;
	memmap_trie *map = vhost_create_memmap_trie();

	printf("\n\n\ntest_vhost_memory_array:\n\n");
	for (i = 0; i < vm_count; i++) {
		unsigned long long j, end;
		assert(vhost_insert_region(map, &vm[i]));
	}

	mem = malloc(sizeof(struct vhost_memory) + sizeof *vm * vm_count);
	memcpy(mem->regions, vm, sizeof *vm * vm_count);
	mem->nregions = vm_count;

//        dump_map(map, &map->root);
        test_lookup(map, mem, vm, vm_count, 10);
	free(mem);
	vhost_free_memmap_trie(map);
}

vhost_memory_region vm1[] = {
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

vhost_memory_region vm2[] = {
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

vhost_memory_region iterator[] = {
{ 0xff00000000000000, 0x100, 0x7fe3b0000000 },

{ 0xff00010000000000, 0x100, 0x7fe3b0000000 },
{ 0xffff000000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffaa0000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100000, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100200, 0x100, 0x7fe3b0000000 },
{ 0xffffff0000100300, 0x1, 0x7fe3b0000000 },
{ 0xffffff0000100301, 0xfe, 0x7fe3b0000000 },

};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
int main(int argc, char **argv)
{
	test_vhost_memory_array(vm1, ARRAY_SIZE(vm1), 1);
//	test_vhost_memory_array(vm2, ARRAY_SIZE(vm2), 0x1000);
	test_vhost_memory_array(level_compression, ARRAY_SIZE(level_compression), 0xfe);
	test_vhost_memory_array(iterator, ARRAY_SIZE(iterator), 0xfe);
	return 0;
}
