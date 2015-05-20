#include "vhost_memmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

static void * ERR_PTR(long error)
{
        return (void *) error;
}


#define UNIFORM_NODE 0
#define NON_UNIFORM_NODE 1

#define IS_LEAF(x) (!((x)->ptr & 1) && (x)->ptr & ~0xfULL)
#define IS_NODE(x) ((x)->ptr & 1 && (x)->ptr & ~0xfULL)
#define MARK_AS_NODE(x) ((x)->ptr |= 1)
#define MARK_AS_LEAF(x) ((x)->ptr &= ~1ULL)
#define IS_FREE(x) (!((x)->ptr & ~0xfULL))
#define NODE_PTR(x) ((x)->ptr >> 4)
#define SET_NODE_PTR(x, v) (x)->ptr = ((x)->ptr & 0xfULL) | (v << 4)
#define NODE_SKIP(x) (((x)->ptr & 0xf) >> 1)
#define SET_NODE_SKIP(x, v) (x)->ptr = (x)->ptr & ~(7ULL << 1) | (((v) & 0xf) << 1)
#define PREFIX_VAL(x) ((unsigned long long)((x)->val) << 4)

memmap_trie *vhost_create_memmap_trie()
{
	trie_node *root_node;

	memmap_trie *map = malloc(sizeof(*map));
	memset(map, 0, sizeof(*map));
	return map;
}

static void node_add_leaf(trie_node_value_t *node_val, unsigned long long ptr)
{
	MARK_AS_LEAF(node_val);
	SET_NODE_PTR(node_val, ptr);
}

static void replace_node(trie_node_value_t *node_val, const trie_node_value_t *new_ptr)
{
	*node_val = *new_ptr;
}

static unsigned long long get_index(const int level, const unsigned long long addr)
{
	int lvl_shift = VHOST_ADDR_BITS - VHOST_RADIX_BITS * (level + 1);
	return (addr >> lvl_shift) & (NODE_WITDH - 1);
}

/* returns common prefix length between addr and prefix */
static int prefix_len(unsigned long long a, unsigned long long b, int max_len)
{
	unsigned depth;
	unsigned long long idx;

	for (depth = 0; depth < max_len; depth++) {
		idx = get_index(depth, b);
		if (get_index(depth, a) != idx)
			break;
	}
	return depth;
}

static trie_prefix *get_node_prefix(memmap_trie *map, trie_node_value_t *node_ptr)
{
	return &node_ptr->prefix;
}

static void set_prefix(trie_prefix *prefix, unsigned long long addr, int len)
{
	addr = addr >> (VHOST_ADDR_BITS - VHOST_RADIX_BITS * len);
	prefix->val = (addr << (VHOST_ADDR_BITS - VHOST_RADIX_BITS * len)) >> 4;
	prefix->len = len;
}

static trie_node *get_trie_node(const trie_node_value_t *node_val)
{
	unsigned long long  addr = NODE_PTR(node_val);
	return (trie_node *)(addr << 4);
}

static vhost_memory_region *get_val(unsigned long long ptr)
{
        return (vhost_memory_region *)(ptr << 4);
}

static trie_node *alloc_node(trie_node_value_t *node_ptr, memmap_trie *map,
				unsigned long long addr, int len, int skip, bool non_uniform) {
	trie_node *new_node;
	trie_prefix *prefix;

	posix_memalign((void **)&new_node, 16, sizeof(*new_node));
	if (!new_node)
		return ERR_PTR(-ENOMEM);

	memset(new_node, 0, sizeof(new_node));
	SET_NODE_PTR(node_ptr, (unsigned long long)new_node >> 4);
	SET_NODE_SKIP(node_ptr, skip);
	MARK_AS_NODE(node_ptr);

	/* initialize node prefix */
	prefix = get_node_prefix(map, node_ptr);
	set_prefix(prefix, addr, len);
	prefix->non_uniform = non_uniform;

	return new_node;
}

static void clear_node_val(trie_node_value_t *node_ptr)
{
	memset(node_ptr, 0, sizeof(*node_ptr));
}

static bool addr_matches_value(trie_node_value_t *node_ptr,
				unsigned long long addr) {
	unsigned long long start, end;

	start = get_val(NODE_PTR(node_ptr))->guest_phys_addr;
	end = get_val(NODE_PTR(node_ptr))->gpa_end;
	if (addr >= start && addr < end)
		return true;

	return false;
}

#define DBG(fmt, ...)
//#define DBG(fmt, ...) printf("%-*d  " fmt, level * 3, level,  __VA_ARGS__)
#define PREFIX_FMT "prefix %.*llx:%d"
#define PREFIX_ARGS(map, ptr) \
	get_node_prefix(map, ptr)->len * 2, get_node_prefix(map, ptr)->val >> \
	(VHOST_ADDR_BITS - VHOST_RADIX_BITS * get_node_prefix(map, ptr)->len), \
	get_node_prefix(map, ptr)->len

/* returns pointer to inserted value or 0 if insert fails */
unsigned long long vhost_insert_region(memmap_trie *map, vhost_memory_region *val)
{
	unsigned i, k, j, n;
	trie_prefix *prefix;
	trie_node *node, *new_node;
	trie_node_value_t new_ptr, *node_ptr = &map->root;
	int level = 0;
	int skip = 0;
	unsigned long long val_ptr = 0;
	unsigned long long addr_inc = 0;
	unsigned long long end = val->guest_phys_addr + val->memory_size;
	unsigned long long addr = val->guest_phys_addr;
	do {
		DBG("=== addr: 0x%llx\tval: %p, inc: 0x%llx\n", addr, val, addr_inc);
		prefix = get_node_prefix(map, node_ptr);
		node = get_trie_node(node_ptr);

		if (!node) { /* path compression at root node */
			int new_node_skip = VHOST_ADDR_BITS/VHOST_RADIX_BITS - 1;
			node = alloc_node(node_ptr, map, addr, new_node_skip,
				 new_node_skip, UNIFORM_NODE);
		}

		/* lazy expand level if new common prefix is smaller than current */
		j = prefix_len(addr, PREFIX_VAL(prefix), prefix->len);
		if (j < prefix->len) { /* prefix mismatch */
			int new_node_skip;

			DBG("Prefix mismatch\n","");
			/* level is not comressible(has different leaves) */
			if (prefix->non_uniform) {
				new_node_skip =	NODE_SKIP(node_ptr) - (j - (level + skip))
					- 1 /* new level will consume 1 skip step */;
				new_node = alloc_node(&new_ptr, map, PREFIX_VAL(prefix),
					 prefix->len, new_node_skip, NON_UNIFORM_NODE);

				/* copy current node to a new one */
				memcpy(new_node, node, sizeof(*new_node));

				DBG("Do lazy exp, new N%llx " PREFIX_FMT " Nskip: %d\n", NODE_PTR(&new_ptr),
					PREFIX_ARGS(map, &new_ptr), NODE_SKIP(&new_ptr));
			} else { /* all childs the same, compress level */
				/*
				 * take pointer to 1st leaf as reference leaf
				 * then wipe curent node and relocate leaf
				 * to a new position with a shorter prefix
				 */
				/* find a leaf */
				for (n = 0; n < NODE_WITDH; n++)
					if (NODE_PTR(&node->val[n]))
						break;

				new_ptr = node->val[n]; /* use 1st leaf as reference */
				if (!addr_matches_value(&node->val[n], addr))
					prefix->non_uniform = NON_UNIFORM_NODE;
				DBG("Do level compression of N%llx\n", NODE_PTR(node_ptr));
			}

			/* form new node in place of current */
			memset(node, 0, sizeof(*node));
			i = get_index(j, PREFIX_VAL(prefix));
			set_prefix(prefix, PREFIX_VAL(prefix), j);
			/* update skip value of current node with new prefix len */
			SET_NODE_SKIP(node_ptr, j - (level + skip));
			replace_node(&node->val[i], &new_ptr);

			DBG("relocate N%llx as %c%llx at N%llx[%x]\n",
				NODE_PTR(node_ptr),
				IS_NODE(&new_ptr) ? 'N' : 'L', NODE_PTR(&new_ptr),
				NODE_PTR(node_ptr), i);
			DBG("addjust N%llx Nskip: %d " PREFIX_FMT "\n",
				NODE_PTR(node_ptr),
				NODE_SKIP(node_ptr), PREFIX_ARGS(map, node_ptr));
		}

		skip += NODE_SKIP(node_ptr);
		i = get_index(level + skip, addr);
		DBG("N%llx[%x]\taddr: %.16llx\tskip: %d\n",
			NODE_PTR(node_ptr), i, addr, skip);
		DBG("N%llx Nskip: %d " PREFIX_FMT "\n", NODE_PTR(node_ptr),
			NODE_SKIP(node_ptr), PREFIX_ARGS(map, node_ptr));
		if (IS_LEAF(&node->val[i])) {
			unsigned long long old_addr, end_addr;
			void *ptr;
			int old_nskip;
			int node_skip;
			val_ptr = NODE_PTR(&node->val[i]);
			vhost_memory_region *old_val = get_val(val_ptr);
			old_addr = old_val->guest_phys_addr;
			end_addr = old_val->guest_phys_addr + old_val->memory_size;

			/* do not split if addr matches the leaf */
			if (addr_matches_value(&node->val[i], addr)) {
				if (val->guest_phys_addr != old_val->guest_phys_addr) {
					// BUGON (new range shouldn't intersect with exiting)
					return 0;
				}
				addr += addr_inc;
				skip -= NODE_SKIP(node_ptr);
				continue;
			}

			DBG("split leaf at N%llx[%x]\n", NODE_PTR(node_ptr), i);
			/* get path prefix and skips for new node */
			j = prefix_len(addr, old_addr, sizeof(addr));
			node_skip = j - (level + skip) - 1 /* for next level */ ;

			/* alloc interim node for relocating old leaf there */
			new_node = alloc_node(&new_ptr, map, old_addr, j,
						 node_skip, NON_UNIFORM_NODE);

			DBG("new N%llx\nset N%llx Nskip: %d " PREFIX_FMT "\n",
				NODE_PTR(&new_ptr),
			NODE_PTR(&new_ptr), node_skip, PREFIX_ARGS(map, &new_ptr));

			/* relocate old leaf to new node reindexing it to new offset */
			addr_inc = 1ULL << (VHOST_ADDR_BITS - (j + 1) * VHOST_RADIX_BITS);
			for ( ; old_addr < end_addr;
				old_addr += addr_inc) {
				k = get_index(j, old_addr);
				if (IS_FREE(&new_node->val[k])) {
				/* do only one insert in case index for addr matches */
					node_add_leaf(&new_node->val[k], val_ptr);
					DBG("relocate L%llx to N%llx[%x]\taddr: %llx\n",
					 val_ptr, NODE_PTR(&new_ptr), k, old_addr);
				}
			}
			replace_node(&node->val[i], &new_ptr);

			/* fall to the next level and let 'addr' leaf be inserted */
			node_ptr = &node->val[i];
			level++; /* +1 for new level */
			val_ptr = 0;
		} else if (IS_FREE(&node->val[i])) {

			if (!val_ptr) {
				posix_memalign((void *)&val_ptr, 16, sizeof(*val));
				val_ptr >>= 4;
				*get_val(val_ptr) = *val;
				get_val(val_ptr)->gpa_end =
					val->guest_phys_addr + val->memory_size;
			}
			node_add_leaf(&node->val[i], val_ptr);

			if (!prefix->non_uniform) {
				/* find a leaf */
				for (n = 0; n < NODE_WITDH; n++)
					if (NODE_PTR(&node->val[n]))
						break;
				if (n < NODE_WITDH &&
				    !addr_matches_value(&node->val[n], addr))
					prefix->non_uniform = NON_UNIFORM_NODE;
			}


			DBG("insert L%llx at N%llx[%x]\taddr: %llx\n",
				val_ptr, NODE_PTR(node_ptr), i, addr);
			addr_inc = 1ULL << (VHOST_ADDR_BITS - (level + skip + 1)
					  	* VHOST_RADIX_BITS);
			addr += addr_inc;
			skip -= NODE_SKIP(node_ptr);
		} else { /* traverse tree */
			node_ptr = &node->val[i];
		        DBG("go to N%llx[%x]\n", NODE_PTR(node_ptr), i);
			level++;
		}
	} while (addr < end);
	return val_ptr;
}


