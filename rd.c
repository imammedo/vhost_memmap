#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct vhost_memory_region {
        uint64_t guest_phys_addr;
        uint64_t memory_size;
        uint64_t userspace_addr;
} vhost_memory_region;

vhost_memory_region vm[] = {
{ 0x100000000, 0x40000000, 0x7fe3b0000000 },
{ 0x200000000, 0x40000000, 0x7fe3b0000000 },
{ 0x400000000, 0x40000000, 0x7fe3b0000000 },
{ 0x0fffc0000, 0x40000, 0x7fe3fdc00000 },
{ 0x000000000, 0xa0000, 0x7fe2f0000000 },
{ 0x0000c0000, 0xbff40000, 0x7fe2f00c0000 },
{ 0x0f8000000, 0x4000000, 0x7fe2e8000000 },
{ 0x0fc054000, 0x2000, 0x7fe3fd600000 }
};

#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << 12)
#define VHOST_PHYS_USED_BITS 44

typedef struct {
	uint16_t leaf: 1;
	uint16_t used: 1;
	uint16_t skip: 3;
	uint16_t rsvd: 4;
	uint16_t ptr:  8;
} trie_node_value_t;

#define RADIX_WIDTH_BITS   8
#define NODE_WITDH (1U << RADIX_WIDTH_BITS)
typedef struct {
	trie_node_value_t val[NODE_WITDH];
} trie_node;

#define LOOKUP_TBLS_MAX 32

#define NODES_PER_TBL (PAGE_SIZE / sizeof(trie_node))
#define LOOKUP_IDX(x) (x / NODES_PER_TBL)
#define NODE_IDX(x) (x % NODES_PER_TBL)

#define VALS_PER_TBL (PAGE_SIZE / sizeof(vhost_memory_region))
#define VAL_TBL_IDX(x) (x / VALS_PER_TBL)
#define VAL_IDX(x) (x % VALS_PER_TBL)

typedef struct {
        int free_node_idx;
        int free_val_idx;
        int lookup_tables_number;
	trie_node *lookup_tables[LOOKUP_TBLS_MAX];
	vhost_memory_region *val_tables[12];
} memmap_trie;

memmap_trie *create_memmap_trie()
{
	memmap_trie *map = malloc(sizeof(*map));
	memset(map, 0, sizeof(*map));
	map->free_node_idx = 0;
	return map;
}

trie_node *alloc_node(memmap_trie *map, int node_ptr)
{
	int i = 0;

        i = LOOKUP_IDX(node_ptr);
	/* alloc lookup table if it doesn't exists */
	if (!map->lookup_tables[i]) {
		map->lookup_tables[i] = malloc(PAGE_SIZE);
		memset(map->lookup_tables[i], 0, PAGE_SIZE);
	}

	return &map->lookup_tables[i][NODE_IDX(node_ptr)];
}

bool is_node_allocated(memmap_trie *map, int node_ptr)
{
	int tbl_idx = LOOKUP_IDX(node_ptr);

	if (!map->lookup_tables[tbl_idx])
		return false;

	return true;
}

trie_node *get_node(memmap_trie *map, int node_ptr)
{
	if (!is_node_allocated(map, node_ptr))
		return alloc_node(map, node_ptr);

	return &map->lookup_tables[LOOKUP_IDX(node_ptr)][NODE_IDX(node_ptr)];
}

vhost_memory_region *alloc_val(memmap_trie *map, int ptr)
{
	int i = 0;

        i = VAL_TBL_IDX(ptr);
	/* alloc lookup table if it doesn't exists */
	if (!map->val_tables[i]) {
		map->val_tables[i] = malloc(PAGE_SIZE);
		memset(map->val_tables[i], 0, PAGE_SIZE);
	}
	return &map->val_tables[i][VAL_IDX(ptr)];
}

bool is_val_allocated(memmap_trie *map, int ptr)
{
	int tbl_idx = VAL_TBL_IDX(ptr);

	if (!map->val_tables[tbl_idx])
		return false;

	return map->val_tables[tbl_idx][VAL_IDX(ptr)].memory_size;
}

vhost_memory_region *get_val(memmap_trie *map, int ptr)
{
	if (!is_val_allocated(map, ptr))
		return alloc_val(map, ptr);

	return &map->val_tables[VAL_TBL_IDX(ptr)][VAL_IDX(ptr)];
}

#define DBG(fmt, ...) printf("%-*d  " fmt, level * 3, level,  __VA_ARGS__)

void insert(memmap_trie *map, uint64_t addr, vhost_memory_region *val, int node_ptr, int val_ptr, int level)
{
	trie_node *node_val;

	DBG("addr: 0x%llx\tval: %p\tval_ptr: %d\n", addr, val, val_ptr);
	addr <<= sizeof(addr) * 8 - VHOST_PHYS_USED_BITS;
	do {
		unsigned i;
		uint64_t saddr;
//		int lvl_shift = RADIX_WIDTH_BITS*(level-1);
		int lvl_shift = 64 - RADIX_WIDTH_BITS*(level-1);


		node_val = get_node(map, node_ptr);
		saddr = addr >> (lvl_shift);
		i = saddr & (NODE_WITDH - 1);
		DBG("ptr: %d\t\ti: %x\taddr: %llx\tsaddr: %llx\n", node_ptr, i, addr, saddr);
		if (node_val->val[i].leaf) {
		DBG("split leaf\ti: %x\n", i);
			/* insert interim node, relocate old leaf there */
			trie_node *new_node_val;
			vhost_memory_region *old_val;
			int old_val_ptr = node_val->val[i].ptr;

			node_ptr = ++map->free_node_idx;
			node_val->val[i].leaf = false;
			node_val->val[i].ptr = node_ptr;

			/* reinsert old value */
			old_val = get_val(map, old_val_ptr);
			level++;
			insert(map, old_val->guest_phys_addr, NULL,
				node_ptr, old_val_ptr, level);
		} else if (!node_val->val[i].used) {
		DBG("insert leaf\ti: %x\taddr: %llx\n", i, addr);
			node_val->val[i].used = true;
			/* empty node, insert leaf here */
			node_val->val[i].leaf = true;
			if (val) { /* new value */
				node_val->val[i].ptr = map->free_val_idx++;
				*get_val(map, node_val->val[i].ptr) = *val;
			} else { /* reuse allocated value, relocate case */
				node_val->val[i].ptr = val_ptr;
			}
			break;

		} else { /* traverse tree */
			node_ptr = node_val->val[i].ptr;
		        DBG("go to ptr: %d\tx: %d\n", node_ptr, i);
			level++;
		}
	} while (1);
}

void compress(memmap_trie *map, int node_ptr)
{
	int i;
	int child_count = 0;
	int compressible_ptr;
	trie_node *node_val = get_node(map, node_ptr);

	/* compress children */
	for (i =0; i < NODE_WITDH; i++) {
		if (node_val->val[i].used && !node_val->val[i].leaf) {
			compress(map, node_val->val[i].ptr);
		}
	}

	/* check if path compressible */
	for (i = 0; i < NODE_WITDH; i++) {
		if (node_val->val[i].used) {
			child_count++;
			compressible_ptr = node_val->val[i].ptr;
		}
	}

	/* do path compression */
	if (child_count == 1) {
		memcpy(node_val, get_node(map, compressible_ptr), sizeof(*node_val));
		for (i = 0; i < NODE_WITDH; i++)
			node_val->val[i].skip++;
	}

}

int ident = 0;
void dump_map(memmap_trie *map, int node_ptr)
{
	trie_node *node_val;
	int i;
	char in[] = "                                                   ";
	in[ident*3] = 0;

        ident++;
	node_val = get_node(map, node_ptr);        
	for (i =0; i < NODE_WITDH; i++) {
		if (node_val->val[i].used) {
			printf("%sN[%d]: idx: %x  skip: %d\n", in, node_ptr, i, node_val->val[i].skip);
			if (node_val->val[i].leaf) {
				vhost_memory_region *v =
					get_val(map, node_val->val[i].ptr);
				printf("%s   L[%d]: a: %lx\n", in,
					 node_val->val[i].ptr,
					 v->guest_phys_addr);
			} else {
				dump_map(map, node_val->val[i].ptr);
			}
		}
	}
        ident--;
}

int main(int argc, char **argv)
{
	int i;
	memmap_trie *map = create_memmap_trie();

	for (i = 0; i < sizeof(vm)/sizeof(vm[0]); i++) {
		insert(map, vm[i].guest_phys_addr, &vm[i], 0, 0, 1);
	}
	compress(map, 0);

        dump_map(map, 0);
}
