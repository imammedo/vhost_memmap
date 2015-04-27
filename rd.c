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
//{ 0x200000000, 0x40000000, 0x7fe3b0000000 },
//{ 0x400000000, 0x40000000, 0x7fe3b0000000 },
//{ 0x000000000, 0x2000, 0x7fe2f0000000 },
//{ 0x0000c0000, 0x00100000, 0x7fe2f00c0000 },
//{ 0x0fffc0000, 0x2000, 0x7fe3fdc00000 },
//{ 0x100000000, 0x10000, 0x7fe3b0000000 },
//{ 0x0f8000000, 0x4000000, 0x7fe2e8000000 },
//{ 0x0fc054000, 0x2000, 0x7fe3fd600000 }
{ 0xaabb020000000000, 0x10000, 0x7fe3b0000000 },
{ 0xaabb021000000000, 0x10000, 0x7fe3b0000000 },
{ 0xaabb010000000000, 0x10000, 0x7fe3b0000000 },
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

typedef struct trie_prefix {
	uint8_t len;
	uint64_t val;
} trie_prefix;

typedef struct {
        int free_node_idx;
        int free_val_idx;
        int lookup_tables_number;
	trie_node *lookup_tables[LOOKUP_TBLS_MAX];
	trie_prefix *prefix_tables[LOOKUP_TBLS_MAX];
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
		map->prefix_tables[i] = malloc(PAGE_SIZE);
		memset(map->lookup_tables[i], 0, PAGE_SIZE);
		memset(map->prefix_tables[i], 0, PAGE_SIZE);
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

trie_prefix *get_node_prefix(memmap_trie *map, int node_ptr)
{
	get_node(map, node_ptr);
	return &map->prefix_tables[LOOKUP_IDX(node_ptr)][NODE_IDX(node_ptr)];
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

void node_add_leaf(trie_node_value_t *node_val, int ptr)
{
	node_val->used = true;
	node_val->leaf = true;
	node_val->ptr = ptr;
}

void replace_node(trie_node_value_t *node_val, int ptr)
{
	node_val->used = true;
	node_val->leaf = false;
	node_val->ptr = ptr;
}

/* returns prt to new node */
trie_node * newnode(memmap_trie *map, int *new_ptr)
{
	*new_ptr = ++map->free_node_idx;
	return get_node(map, *new_ptr);
}

uint64_t get_index(int level, uint64_t addr)
{
	int lvl_shift = 64 - RADIX_WIDTH_BITS * (level + 1);
	return (addr >> lvl_shift) & (NODE_WITDH - 1);
}

/* return previous skip value */
int set_skip(trie_node *node_val, int skip)
{
	int i;
	int old_skip = node_val->val[i].skip;

	for (i = 0;  i < NODE_WITDH; i++) {
		node_val->val[i].skip = skip;
	}
	return old_skip;
}

void insert(memmap_trie *map, uint64_t addr, vhost_memory_region *val, int node_ptr, int level)
{
	trie_node *node_val;
	int skip = 0;

	DBG("addr: 0x%llx\tval: %p\n", addr, val);
	do {
		unsigned i;
		trie_prefix *prefix = get_node_prefix(map, node_ptr);

		node_val = get_node(map, node_ptr);
		skip += node_val->val[0].skip;

		i = get_index(level + skip, addr);
		DBG("ptr: %d\t\ti: %x\taddr: %llx\tskip: %d\n", node_ptr, i, addr, skip);
		DBG("prefix:  %.16llx:%d\n", prefix->val, prefix->len);
		if (node_val->val[i].leaf) {
			trie_prefix *nprefix;
			trie_node *new_node;
			uint64_t old_addr;
			int old_nskip;
			int new_ptr;
			int k, j;
			int node_skip;
			int val_ptr = node_val->val[i].ptr;
			vhost_memory_region *old_val = get_val(map, val_ptr);
			old_addr = old_val->guest_phys_addr;

			/* insert interim node, relocate old leaf there */
			new_node = newnode(map, &new_ptr);
			nprefix = get_node_prefix(map, new_ptr);
			DBG("new node ptr: %d\n", new_ptr);

			/* compare prefix */
			for (j = 0; j < (prefix->len - 1); j++) {
				k = get_index(j, prefix->val);
				if (get_index(j, addr) != k)
					break;
			}
			if (j < prefix->len) { /* prefix mismatch */
				DBG("prefix mismatch, relocate current N%d\n", node_ptr);
				memcpy(new_node, node_val, sizeof(*new_node));
				*nprefix = *get_node_prefix(map, node_ptr);
				/* form new node in place of current */
				skip -= node_val->val[0].skip;
				memset(node_val, 0, sizeof(*node_val));
				prefix->len = j;
				set_skip(node_val, j - (level + skip));
				i = get_index(level + skip, prefix->val);
				replace_node(&node_val->val[i], new_ptr);
				continue;
			}


			DBG("split leaf\ti: %x\n", i);

			level++; /* +1 for new level */
			/* compare with path prefix */
			for (j = level + skip; j * RADIX_WIDTH_BITS < 64; j++) {
				k = get_index(j, old_addr);
				if (get_index(j, addr) != k)
					break;
			}
			node_skip = j - (level + skip);
			set_skip(new_node, node_skip);
			/* adjust prefix to incl. skipped bits */
			for (j = 0; node_skip && j < node_skip + level + skip; j++) {
				nprefix->len += 1;
				nprefix->val |= get_index(j, old_addr) << (64 - RADIX_WIDTH_BITS * (j + 1));
			}
			DBG("adjusted node prefix: 0x%.16llx:%d\n", nprefix->val, nprefix->len);

			/* relocate old leafs to new node */
			node_add_leaf(&new_node->val[k], val_ptr);
			DBG("relocate leaf ptr %d to k: %x\taddr: %llx\n"
			, val_ptr, k, old_addr);

			replace_node(&node_val->val[i], new_ptr);
			node_ptr = new_ptr;
			/* fall through and let 'addr' leaf be inserted */
		} else if (!node_val->val[i].used) {
			int val_ptr = map->free_val_idx++;

			*get_val(map, val_ptr) = *val;
			node_add_leaf(&node_val->val[i], val_ptr);
			DBG("insert leaf\ti: %x\taddr: %llx\n", i, addr);
			break;

		} else { /* traverse tree */
			node_ptr = node_val->val[i].ptr;
		        DBG("go to ptr: %d\ti: %x\n", node_ptr, i);
			level++;
		}
	} while (1);
}

void lookup(memmap_trie *map, uint64_t addr)
{
	vhost_memory_region *v;
	trie_node *node_val;
	int node_ptr = 0;
	int level = 1;
	unsigned i;

	do {
		i = get_index(level, addr);
		printf("addr: %llx, i: %x, level: %d\n", addr, i, level);
		node_val = get_node(map, node_ptr);
		if (!node_val->val[i].used) {
			printf("Lookup: %llx -> notfound at %x\n", addr, i);
			return;
		}
		if (!node_val->val[i].leaf) {
			node_ptr = node_val->val[i].ptr;
			level++;
			continue;
		}
		break;
	} while (1);
	printf("Lookup: %llx -> N[%d]: ", addr, node_ptr, node_val->val[i].skip);
	if (node_val->val[i].leaf) {
		v = get_val(map, node_val->val[i].ptr);
		printf("L[%d]: a: %lx\n", node_val->val[i].ptr, v->guest_phys_addr);
	}
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
		insert(map, vm[i].guest_phys_addr, &vm[i], 0, 0);
       // 	dump_map(map, 0);
	}
//	compress(map, 0);

        dump_map(map, 0);
	printf("---\n");
        //lookup(map, 0);
        lookup(map, 0xd0000);
}
