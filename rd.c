#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct vhost_memory_region {
        uint64_t guest_phys_addr;
        uint64_t memory_size;
        uint64_t userspace_addr;
        uint64_t gpa_end;
} vhost_memory_region __attribute__((aligned (32)));

struct vhost_memory {
        uint32_t nregions;
        uint32_t padding;
        struct vhost_memory_region regions[0];
};

#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << 12)
#define VHOST_PHYS_USED_BITS 44

typedef struct {
	uint16_t not_leaf: 1;
	uint16_t skip: 4;
	uint16_t rsvd: 4;
	uint16_t ptr:  8;
} trie_node_value_t __attribute__((aligned (4)));

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
	uint64_t val;
	uint8_t len;
	bool in_use;
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
	map->free_val_idx = 1;
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

inline const trie_node *node_fetch(const memmap_trie *map, const int node_ptr)
{
	return &map->lookup_tables[LOOKUP_IDX(node_ptr)][NODE_IDX(node_ptr)];
}


trie_node *get_node(memmap_trie *map, int node_ptr)
{
	if (!is_node_allocated(map, node_ptr))
		return alloc_node(map, node_ptr);

	return (trie_node *)node_fetch(map, node_ptr);
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

inline const vhost_memory_region *val_fetch(const memmap_trie *map, const int ptr)
{
	return &map->val_tables[VAL_TBL_IDX(ptr)][VAL_IDX(ptr)];
}

vhost_memory_region *get_val(memmap_trie *map, int ptr)
{
	if (!is_val_allocated(map, ptr))
		return alloc_val(map, ptr);

	return (vhost_memory_region *)val_fetch(map, ptr);
}

#define DBG(fmt, ...) printf("%-*d  " fmt, level * 3, level,  __VA_ARGS__)

void node_add_leaf(trie_node_value_t *node_val, int ptr)
{
	node_val->not_leaf = false;
	node_val->ptr = ptr;
}

void replace_node(trie_node_value_t *node_val, int ptr, bool leaf)
{
	node_val->not_leaf = !leaf;
	node_val->ptr = ptr;
}

/* returns prt to new node */
trie_node * newnode(memmap_trie *map, int *new_ptr)
{
	*new_ptr = ++map->free_node_idx;
	return get_node(map, *new_ptr);
}

inline const uint64_t get_index(const int level, const uint64_t addr)
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

/* returns common prefix length between addr and prefix */
int prefix_len(uint64_t a, uint64_t b, int max_len)
{
	unsigned depth;
	uint64_t idx;

	for (depth = 0; depth < max_len; depth++) {
		idx = get_index(depth, b);
		if (get_index(depth, a) != idx)
			break;
	}
	return depth;
}

void set_prefix(trie_prefix *prefix, uint64_t addr, int len)
{
	addr = addr >> (64 - RADIX_WIDTH_BITS * len);
	prefix->val = addr << (64 - RADIX_WIDTH_BITS * len);
	prefix->len = len;
}

#define DBG(...)
/* returns pointer to inserted value or 0 if insert fails */
int insert(memmap_trie *map, uint64_t addr, vhost_memory_region *val, int val_ptr, int node_ptr, int level)
{
	trie_node *node_val;
	int skip = 0;

	DBG("=== addr: 0x%llx\tval: %p\n", addr, val);
	do {
		unsigned i, k, j, n;
		trie_prefix *nprefix;
		trie_node *new_node;
		int new_ptr;
		trie_prefix *prefix = get_node_prefix(map, node_ptr);

		node_val = get_node(map, node_ptr);

		/* path compression at root node */
		if (!prefix->in_use) {
			uint64_t old_addr;

			/* find a leaf so we could try get common prefix */
			for (i = 0; i < NODE_WITDH; i++)
				if (!node_val->val[i].not_leaf && node_val->val[i].ptr)
					break;

			if (i < NODE_WITDH) { /* have leaf to compare */
				/*
				 *  disable path compression at root for next inserts
				 *  since path will be already compressed if compressable
				 */
				prefix->in_use = true;

				val_ptr = node_val->val[i].ptr;
				old_addr = get_val(map, val_ptr)->guest_phys_addr;
				j = prefix_len(addr, old_addr, sizeof(addr));
				if (j) { /* compress path using common prefix */
					k = get_index(j, old_addr);
					set_prefix(prefix, old_addr, j);
					set_skip(node_val, prefix->len);
					DBG("Compress N%d with prefix: %.16llx:%d\n",
						node_ptr, prefix->val, prefix->len);
					/* relocate old leaf to new slot */
					node_val->val[i].not_leaf = true;
					node_val->val[i].ptr = 0;
					node_add_leaf(&node_val->val[k], val_ptr);
					DBG("relocate L%d to N%d[%x]\taddr: %llx\n",
						val_ptr, node_ptr, k, old_addr);
					/* fall through to insert 'addr' in compressed node */
				}
			}
		}

		/* lazy expand level if new common prefix is smaller than current */
		j = prefix_len(addr, prefix->val, prefix->len);
		if (j < prefix->len) { /* prefix mismatch */
			/* check that current node could be level compressed */
			for (n = 0; n < NODE_WITDH; n++) /* find first used node */
				if (node_val->val[n].ptr)
					break;

			/* check if all pointers the same and more than 1 */
			for (k = 0, i = 0; n < NODE_WITDH && k < NODE_WITDH; k++) {
				if (node_val->val[k].ptr) {
					if (node_val->val[k].ptr != node_val->val[n].ptr)
						break;
					if (node_val->val[k].ptr == node_val->val[n].ptr)
						i++;
				}
			}

			/* level is not comressible(has different leaves)
			 * or has 1 leaf only
			 */
			if (i == 1 || k < NODE_WITDH) {
				/* copy current node to a new one */
				new_node = newnode(map, &new_ptr);
				nprefix = get_node_prefix(map, new_ptr);
				memcpy(new_node, node_val, sizeof(*new_node));
				*nprefix = *get_node_prefix(map, node_ptr);
				set_skip(new_node,
					new_node->val[0].skip - (j - (level + skip))
					- 1 /* new level will consume 1 skip step */);
				DBG("new N%d prefix %.*llx:%d skip: %d\n", new_ptr,
					nprefix->len * 2,
					nprefix->val >> (64 - RADIX_WIDTH_BITS * nprefix->len),
					nprefix->len, new_node->val[0].skip);
			} else { /* all childs the same, compress level */
				DBG("Do level compression of N%d\n", node_ptr);
				new_ptr = node_val->val[0].ptr;
			}

			/* form new node in place of current */
			memset(node_val, 0, sizeof(*node_val));
			i = get_index(j, prefix->val);
			set_prefix(prefix, prefix->val, j);
			set_skip(node_val, j - (level + skip));
			replace_node(&node_val->val[i], new_ptr, k < NODE_WITDH ? 0 : 1);
			DBG("Prefix mismatch, relocate N%d to N%d at N%d[%x]\n", node_ptr, new_ptr, node_ptr, i);
			DBG("addjust prefix %.*llx:%d\n", prefix->len * 2,
				prefix->val >> (64 - RADIX_WIDTH_BITS * prefix->len),
				prefix->len);
		}


		skip += node_val->val[0].skip;
		i = get_index(level + skip, addr);
		DBG("N%d[%x]\taddr: %.16llx\tskip: %d\n", node_ptr, i, addr, skip);
		DBG("N%d prefix: %.*llx:%d Nskip: %d\n", node_ptr, prefix->len * 2,
			 prefix->val >> (64 - RADIX_WIDTH_BITS * prefix->len),
			 prefix->len, node_val->val[0].skip);
		if (!node_val->val[i].not_leaf && node_val->val[i].ptr) {
			uint64_t old_addr, end_addr;
			int old_nskip;
			int node_skip;
			val_ptr = node_val->val[i].ptr;
			vhost_memory_region *old_val = get_val(map, val_ptr);
			old_addr = old_val->guest_phys_addr;
			end_addr = old_val->guest_phys_addr + old_val->memory_size;

			/* do not expand if addr matches to leaf */
			if (addr >= old_val->guest_phys_addr && addr < end_addr) {
				if (val && val != old_val) {
					// BUGON (new range shouldn't intersect with exiting)
					return 0;
				}
				break;
			}

			DBG("split leaf at N%d[%x]\n", node_ptr, i);
			/* insert interim node, relocate old leaf there */
			new_node = newnode(map, &new_ptr);
			nprefix = get_node_prefix(map, new_ptr);
			*nprefix = *prefix;
			DBG("new N%d\n", new_ptr);

			/* get path prefix and skips for new node */
			j = prefix_len(addr, old_addr, sizeof(addr));
			set_prefix(nprefix, old_addr, j);
			node_skip = j - (level + skip) - 1 /* for next level */ ;
			set_skip(new_node, node_skip);
			DBG("set N%d Nskip: %d prefix: 0x%.*llx:%d\n",
			 new_ptr, node_skip, nprefix->len * 2,
			 nprefix->val  >> (64 - RADIX_WIDTH_BITS * nprefix->len),
			 nprefix->len);

			/* relocate old leaf to new node reindexing it to new offset */
			for (; old_addr < end_addr; old_addr++) {
				k = get_index(j, old_addr);
				if (!new_node->val[k].ptr) {
					node_add_leaf(&new_node->val[k], val_ptr);
					DBG("relocate L%d to N%d[%x]\taddr: %llx\n"
							, val_ptr, new_ptr, k, old_addr);
				}
			}

			replace_node(&node_val->val[i], new_ptr, 0);
			node_ptr = new_ptr;
			/* fall to the next level and let 'addr' leaf be inserted */
			level++; /* +1 for new level */
		} else if (!node_val->val[i].ptr) {
			if (val) {
				val_ptr = map->free_val_idx++;
				val->gpa_end = val->guest_phys_addr + val->memory_size;
				*get_val(map, val_ptr) = *val;
			}
			node_add_leaf(&node_val->val[i], val_ptr);
			DBG("insert L%d at N%d[%x]\taddr: %llx\n", val_ptr, node_ptr, i, addr);
			break;

		} else { /* traverse tree */
			node_ptr = node_val->val[i].ptr;
		        DBG("go to N%d[%x]\n", node_ptr, i);
			level++;
		}
	} while (1);
	return val_ptr;
}

#define unlikely(x)     __builtin_expect(!!(x), 0)
#define likely(x)     __builtin_expect(!!(x), 1)

const vhost_memory_region *lookup(memmap_trie *map, const uint64_t addr)
{
	const vhost_memory_region *v;
	const trie_node *node;
	int val_ptr;
	int node_ptr = 0;
	int level = 0, skip = 0;
	unsigned i;

	do {
		node = node_fetch(map, node_ptr);
		skip += node->val[0].skip;
		i = get_index(level + skip, addr);
		node_ptr = node->val[i].ptr;
		level++;
	} while (node->val[i].not_leaf);

	if (unlikely(!node_ptr)) return NULL;

	val_ptr = node->val[i].ptr;
	v = val_fetch(map, val_ptr);
	if ((v->guest_phys_addr > addr) && (v->gpa_end <= addr))
		return NULL;

	return v;
}

int ident = 0;
void dump_map(memmap_trie *map, int node_ptr)
{
	trie_node *node_val;
	int i;
	char in[] = "                                                   ";
	in[ident*3] = 0;
	trie_prefix *nprefix = get_node_prefix(map, node_ptr);

        ident++;
	node_val = get_node(map, node_ptr);
	for (i =0; i < NODE_WITDH; i++) {
		if (node_val->val[i].ptr) {
			printf("%sN%d[%x]  skip: %d prefix: %.*llx:%d\n", in, node_ptr, i, node_val->val[i].skip, nprefix->len * 2, nprefix->val >> (64 - RADIX_WIDTH_BITS * nprefix->len), nprefix->len);
			if (!node_val->val[i].not_leaf) {
				vhost_memory_region *v =
					get_val(map, node_val->val[i].ptr);
				printf("%s   L%d: a: %.16llx\n", in,
					 node_val->val[i].ptr,
					 v->guest_phys_addr);
			} else {
				dump_map(map, node_val->val[i].ptr);
			}
		}
	}
        ident--;
}

struct vhost_memory_region *find_region(struct vhost_memory *mem,
                                                     uint64_t addr, uint32_t len)
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

void test_lookup(memmap_trie *map, struct vhost_memory *mem, vhost_memory_region *vm, int vm_count, uint64_t step)
{
	int i;
	
	step = step ? step : 1;
	for (i = 0; i < vm_count; i++) {
		uint64_t addr, end;

		end = vm[i].guest_phys_addr + vm[i].memory_size;
		for (addr = vm[i].guest_phys_addr; addr < end; addr += step) {
		if (!lookup(map, addr)) {
				printf("addr: %.16llx\n", addr);
				assert(0);
			};
			assert(find_region(mem, addr, 0));
		}
	}
}

void test_vhost_memory_array(vhost_memory_region *vm, int vm_count, uint64_t step)
{
	int i;
	struct vhost_memory *mem;
	memmap_trie *map = create_memmap_trie();

	printf("\n\n\ntest_vhost_memory_array:\n\n");
	for (i = 0; i < vm_count; i++) {
		uint64_t j, end;
		int val_ptr = 0xff;
		
		end = vm[i].guest_phys_addr + vm[i].memory_size;
		for (j = vm[i].guest_phys_addr; j < end; j += step) {
			bool start = j == vm[i].guest_phys_addr;
			val_ptr = insert(map, j, start ? &vm[i] : NULL, val_ptr, 0, 0);
			if (!val_ptr) dump_map(map, 0);
			assert(val_ptr);
		}
	}

	mem = malloc(sizeof(struct vhost_memory) + sizeof *vm * vm_count);
	memcpy(mem->regions, vm, sizeof *vm * vm_count);
	mem->nregions = vm_count;

//        dump_map(map, 0);
        test_lookup(map, mem, vm, vm_count, 10);
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



#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

int main(int argc, char **argv)
{
//	test_vhost_memory_array(vm1, ARRAY_SIZE(vm1), 1);
	test_vhost_memory_array(vm2, ARRAY_SIZE(vm2), PAGE_SIZE);
	return 0;
}
