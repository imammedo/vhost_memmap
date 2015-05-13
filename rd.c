#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
	uint64_t is_node: 1;
	uint64_t skip: 3;
	uint64_t ptr:  60;
	uint64_t pad;
} trie_node_value_t __attribute__((aligned (16)));

#define IS_LEAF(x) (!x.is_node && x.ptr)
#define IS_NODE(x) (x.is_node && x.ptr)
#define IS_FREE(x) (!x.ptr)
#define NODE_PTR(x) (x)->ptr
#define SET_NODE_PTR(x, v) (x)->ptr = v

#define RADIX_WIDTH_BITS   8
#define NODE_WITDH (1U << RADIX_WIDTH_BITS)
typedef struct {
	trie_node_value_t val[NODE_WITDH];
} trie_node;

typedef struct trie_prefix {
	uint64_t node_ptr;
	uint64_t val;
	uint8_t len;
	bool in_use;
} trie_prefix;

typedef struct {
	trie_node_value_t root;
	trie_prefix prefixes[256];
} memmap_trie ;

memmap_trie *create_memmap_trie()
{
	trie_node *root_node;

	memmap_trie *map = malloc(sizeof(*map));
	memset(map, 0, sizeof(*map));
	posix_memalign((void **)&root_node, 16, sizeof(trie_node));
	memset(root_node, 0, sizeof(trie_node));
	SET_NODE_PTR(&map->root, (uint64_t)root_node >> 4);
	map->root.is_node = 1;
	return map;
}

void node_add_leaf(trie_node_value_t *node_val, uint64_t ptr)
{
	node_val->is_node = false;
	SET_NODE_PTR(node_val, ptr);
}

static void replace_node(trie_node_value_t *node_val, const trie_node_value_t *new_ptr)
{
	*node_val = *new_ptr;
}

const uint64_t get_index(const int level, const uint64_t addr)
{
	int lvl_shift = 64 - RADIX_WIDTH_BITS * (level + 1);
	return (addr >> lvl_shift) & (NODE_WITDH - 1);
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

trie_prefix *get_node_prefix(memmap_trie *map, trie_node_value_t *node_ptr)
{
	int i;
	const end = sizeof(map->prefixes)/sizeof(*map->prefixes);

	for (i = 0; i < end && map->prefixes[i].node_ptr; i++) {
		if (map->prefixes[i].node_ptr == NODE_PTR(node_ptr))
			return &map->prefixes[i]; 
	}

	assert(i < end);
	map->prefixes[i].node_ptr = NODE_PTR(node_ptr);
	return &map->prefixes[i];
}

void set_prefix(trie_prefix *prefix, uint64_t addr, int len)
{
	addr = addr >> (64 - RADIX_WIDTH_BITS * len);
	prefix->val = addr << (64 - RADIX_WIDTH_BITS * len);
	prefix->len = len;
	prefix->in_use = true;
}

#define DBG(...)
//#define DBG(fmt, ...) printf("%-*d  " fmt, level * 3, level,  __VA_ARGS__)
#define PREFIX_FMT "prefix %.*llx:%d"
#define PREFIX_ARGS(map, ptr) \
	get_node_prefix(map, ptr)->len * 2, get_node_prefix(map, ptr)->val >> \
	(64 - RADIX_WIDTH_BITS * get_node_prefix(map, ptr)->len), \
	get_node_prefix(map, ptr)->len


trie_node *get_trie_node(const trie_node_value_t *node_val)
{
	uint64_t  addr = NODE_PTR(node_val);
	return (trie_node *)(addr << 4);
}

vhost_memory_region *get_val(uint64_t ptr)
{
        return (vhost_memory_region *)(ptr << 4);
}

static inline void * ERR_PTR(long error)
{
        return (void *) error;
}

static trie_node *alloc_node(trie_node_value_t *node_ptr, memmap_trie *map,
				uint64_t addr, int len, int skip) {
	trie_node *new_node;
	trie_prefix *prefix;

	posix_memalign((void **)&new_node, 16, sizeof(*new_node));
	if (!new_node)
		return ERR_PTR(-ENOMEM);

	memset(new_node, 0, sizeof(new_node));
	SET_NODE_PTR(node_ptr, (unsigned long long)new_node >> 4);
	node_ptr->skip = skip;
	node_ptr->is_node = 1;

	/* initialize node prefix */
	prefix = get_node_prefix(map, node_ptr);
	set_prefix(prefix, addr, len);

	return new_node;
}

static void clear_node_val(trie_node_value_t *node_ptr)
{
	memset(node_ptr, 0, sizeof(*node_ptr));
}

/* returns pointer to inserted value or 0 if insert fails */
uint64_t insert(memmap_trie *map, uint64_t addr, vhost_memory_region *val, uint64_t val_ptr)
{
	unsigned i, k, j, n;
	trie_prefix *prefix;
	trie_node *node, *new_node;
	trie_node_value_t new_ptr, *node_ptr = &map->root;
	int level = 0;
	int skip = 0;

	DBG("=== addr: 0x%llx\tval: %p\n", addr, val);
	do {
		prefix = get_node_prefix(map, node_ptr);
		node = get_trie_node(node_ptr);

		/* path compression at root node */
		if (!prefix->in_use) { /* only root node can be without prefix set */
			uint64_t old_addr;

			/* find a leaf so we could try get common prefix */
			for (i = 0; i < NODE_WITDH; i++)
				if (IS_LEAF(node->val[i]))
					break;

			if (i < NODE_WITDH) { /* have leaf to compare */
				val_ptr = NODE_PTR(&node->val[i]);
				old_addr = get_val(val_ptr)->guest_phys_addr; /*TODO: is it ok to use guest_phys_addr as base */
				j = prefix_len(addr, old_addr, sizeof(addr));
				/*
				 *  disables path compression at root for next inserts
				 *  since path will be already compressed if compressable
				 */
				set_prefix(prefix, old_addr, j);
				if (j) { /* compress path using common prefix */
					k = get_index(j, old_addr);

					node_ptr->skip = prefix->len;
					/* relocate old leaf to new slot */
					clear_node_val(&node->val[i]);
					node_add_leaf(&node->val[k], val_ptr);
					DBG("Compress N%llx with prefix: %.16llx:%d\n",
						NODE_PTR(node_ptr), prefix->val, prefix->len);
					DBG("Relocate L%llx to N%llx[%x]\taddr: %llx\n",
						val_ptr, NODE_PTR(node_ptr), k, old_addr);
					/* fall through to insert 'addr' in compressed node */
				}
			}
		}

		/* lazy expand level if new common prefix is smaller than current */
		j = prefix_len(addr, prefix->val, prefix->len);
		if (j < prefix->len) { /* prefix mismatch */
			int new_node_skip;

			DBG("Prefix mismatch\n","");
			/* check if current node could be level compressed */
			for (n = 0; n < NODE_WITDH; n++) /* find first used node */
				if (NODE_PTR(&node->val[n]))
					break;

			/* check if all pointers the same and more than 1 */
			for (k = 0, i = 0; n < NODE_WITDH && k < NODE_WITDH; k++) {
				if (NODE_PTR(&node->val[k])) {
					if (NODE_PTR(&node->val[k]) != NODE_PTR(&node->val[n]))
						break;
					if (NODE_PTR(&node->val[k]) == NODE_PTR(&node->val[n]))
						i++;
				}
			}

			/* level is not comressible(has different leaves)
			 * or has 1 leaf only
			 */
			if (i == 1 || k < NODE_WITDH) {
				new_node_skip =	node_ptr->skip - (j - (level + skip))
					- 1 /* new level will consume 1 skip step */;
				new_node = alloc_node(&new_ptr, map, prefix->val, prefix->len,
							new_node_skip);

				/* copy current node to a new one */
				memcpy(new_node, node, sizeof(*new_node));

				DBG("new N%llx " PREFIX_FMT " Nskip: %d\n", NODE_PTR(&new_ptr),
					PREFIX_ARGS(map, &new_ptr), new_ptr.skip);
			} else { /* all childs the same, compress level */
				/*
				 * take pointer to 1st leaf as reference leaf
				 * then wipe curent node and relocate leaf
				 * to a new position with a shorter prefix
				 */
				DBG("Do level compression of N%llx\n", NODE_PTR(node_ptr));
				new_ptr = node->val[n]; /* use 1st leaf as reference */
			}

			/* form new node in place of current */
			memset(node, 0, sizeof(*node));
			i = get_index(j, prefix->val);
			set_prefix(prefix, prefix->val, j);
			/* update skip value of current node with new prefix len */
			node_ptr->skip = j - (level + skip);
			replace_node(&node->val[i], &new_ptr);

			DBG("relocate N%llx as %c%llx at N%llx[%x]\n", NODE_PTR(node_ptr),
				IS_NODE(new_ptr) ? 'N' : 'L', new_ptr.ptr, NODE_PTR(node_ptr), i);
			DBG("addjust N%llx Nskip: %d " PREFIX_FMT "\n", NODE_PTR(node_ptr),
				 node_ptr->skip, PREFIX_ARGS(map, node_ptr));
		}

		skip += node_ptr->skip;
		i = get_index(level + skip, addr);
		DBG("N%llx[%x]\taddr: %.16llx\tskip: %d\n", NODE_PTR(node_ptr), i, addr, skip);
		DBG("N%llx Nskip: %d " PREFIX_FMT "\n", NODE_PTR(node_ptr), node_ptr->skip,
			 PREFIX_ARGS(map, node_ptr));
		if (IS_LEAF(node->val[i])) {
			uint64_t old_addr, end_addr;
			void *ptr;
			int old_nskip;
			int node_skip;
			val_ptr = NODE_PTR(&node->val[i]);
			vhost_memory_region *old_val = get_val(val_ptr);
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

			DBG("split leaf at N%llx[%x]\n", NODE_PTR(node_ptr), i);
			/* get path prefix and skips for new node */
			j = prefix_len(addr, old_addr, sizeof(addr));
			node_skip = j - (level + skip) - 1 /* for next level */ ;

			/* alloc interim node for relocating old leaf there */
			new_node = alloc_node(&new_ptr, map, old_addr, j, node_skip);

			DBG("new N%llx\nset N%llx Nskip: %d " PREFIX_FMT "\n", NODE_PTR(&new_ptr),
			 NODE_PTR(&new_ptr), node_skip, PREFIX_ARGS(map, &new_ptr));

			/* relocate old leaf to new node reindexing it to new offset */
			for (; old_addr < end_addr; old_addr++) {
				k = get_index(j, old_addr);
				if (IS_FREE(new_node->val[k])) {
				/* do only one insert in case index for addr matches */
					node_add_leaf(&new_node->val[k], val_ptr);
					DBG("relocate L%llx to N%llx[%x]\taddr: %llx\n"
							, val_ptr, NODE_PTR(&new_ptr), k, old_addr);
				}
			}
			replace_node(&node->val[i], &new_ptr);

			/* fall to the next level and let 'addr' leaf be inserted */
			node_ptr = &node->val[i];
			level++; /* +1 for new level */
		} else if (IS_FREE(node->val[i])) {
			if (val) {
				posix_memalign((void *)&val_ptr, 16, sizeof(*val));
				val_ptr >>= 4;
				*get_val(val_ptr) = *val;
				get_val(val_ptr)->gpa_end = val->guest_phys_addr + val->memory_size;
			}
			node_add_leaf(&node->val[i], val_ptr);
			DBG("insert L%llx at N%llx[%x]\taddr: %llx\n", val_ptr, NODE_PTR(node_ptr), i, addr);
			break;

		} else { /* traverse tree */
			node_ptr = &node->val[i];
		        DBG("go to N%llx[%x]\n", NODE_PTR(node_ptr), i);
			level++;
		}
	} while (1);
	return val_ptr;
}

#define unlikely(x)     __builtin_expect(!!(x), 0)
#define likely(x)     __builtin_expect(!!(x), 1)

const inline vhost_memory_region *lookup(uint64_t node_ptr, const uint64_t addr)
{
	const vhost_memory_region *v;
	unsigned i;
	uint64_t a = addr;

	do {
		const trie_node *node;

		a <<= RADIX_WIDTH_BITS * (((uint8_t)node_ptr & 0xF) >> 1);
		i = a >> (64 - RADIX_WIDTH_BITS);
		a <<= RADIX_WIDTH_BITS;
		node = (trie_node *)(node_ptr & ~0xF);
		node_ptr = *(const uint64_t *)(&node->val[i]);
	} while ((uint8_t)node_ptr & 0xF);

	v = (vhost_memory_region *)(node_ptr);
	if (likely(v) && likely(v->guest_phys_addr <= addr) && likely(v->gpa_end > addr))
		return v;

	return NULL;
}

int ident = 0;
void dump_map(memmap_trie *map, trie_node_value_t *node_ptr)
{
	trie_node *node_val;
	int i;
	char in[] = "                                                   ";
	in[ident*3] = 0;
	trie_prefix *nprefix = get_node_prefix(map, node_ptr);

        ident++;
	node_val = get_trie_node(node_ptr);
	for (i =0; i < NODE_WITDH; i++) {
		if (!IS_FREE(node_val->val[i])) {
			printf("%sN%llx[%x]  skip: %d prefix: %.*llx:%d\n", in, NODE_PTR(node_ptr), i, node_ptr->skip, nprefix->len * 2, nprefix->val >> (64 - RADIX_WIDTH_BITS * nprefix->len), nprefix->len);
			if (IS_LEAF(node_val->val[i])) {
				vhost_memory_region *v =
					get_val(NODE_PTR(&node_val->val[i]));
				printf("%s   L%llx: a: %.16llx\n", in,
					 NODE_PTR(&node_val->val[i]),
					 v->guest_phys_addr);
			} else {
				dump_map(map, &node_val->val[i]);
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
		if (!lookup(*(uint64_t *)&map->root, addr)) {
				dump_map(map, &map->root);
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
		uint64_t val_ptr;
		
		end = vm[i].guest_phys_addr + vm[i].memory_size;
		for (j = vm[i].guest_phys_addr; j < end; j += step) {
			bool start = j == vm[i].guest_phys_addr;
			val_ptr = insert(map, j, start ? &vm[i] : NULL, val_ptr);
			if (!val_ptr) dump_map(map, &map->root);
			assert(val_ptr);
		}
	}

	mem = malloc(sizeof(struct vhost_memory) + sizeof *vm * vm_count);
	memcpy(mem->regions, vm, sizeof *vm * vm_count);
	mem->nregions = vm_count;

        //dump_map(map, &map->root);
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

vhost_memory_region level_compression[] = {
{ 0x0000000000000000, 0x100, 0x7fe3b0000000 },
{ 0x0000000000100000, 0x1, 0x7fe3b0000000 },
};


#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

int main(int argc, char **argv)
{
	test_vhost_memory_array(vm1, ARRAY_SIZE(vm1), 1);
	test_vhost_memory_array(vm2, ARRAY_SIZE(vm2), PAGE_SIZE);
	test_vhost_memory_array(level_compression, ARRAY_SIZE(level_compression), 0xfe);
	return 0;
}
