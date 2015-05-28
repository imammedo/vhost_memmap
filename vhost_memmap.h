#ifndef vhost_memmap_h
#define vhost_memmap_h

#define likely(x)     __builtin_expect(!!(x), 1)

typedef struct vhost_memory_region {
        unsigned long long guest_phys_addr;
        unsigned long long memory_size;
        unsigned long long userspace_addr;
        unsigned long long gpa_end;
} vhost_memory_region __attribute__((aligned (32)));

typedef struct trie_prefix {
	unsigned long long len:3;
	unsigned long long val:60;
	unsigned long long non_uniform:1;
} trie_prefix;

typedef struct {
	unsigned long long ptr;
	trie_prefix prefix;
} trie_node_value_t __attribute__((aligned (16)));

#define VHOST_RADIX_BITS   8
#define VHOST_ADDR_BITS (sizeof(unsigned long long) * 8)
#define NODE_WITDH (1ULL << VHOST_RADIX_BITS)

typedef struct {
	trie_node_value_t val[NODE_WITDH];
} trie_node;

typedef struct {
	trie_node_value_t root;
} memmap_trie ;

memmap_trie *vhost_create_memmap_trie();

static const inline vhost_memory_region *lookup_region(unsigned long long node_ptr,
		 const unsigned long long addr)
{
	const vhost_memory_region *v;
	unsigned i;
	unsigned long long a = addr;

	do {
		const trie_node *node;

		a <<= VHOST_RADIX_BITS * (((unsigned char)node_ptr & 0xF) >> 1);
		i = a >> (VHOST_ADDR_BITS - VHOST_RADIX_BITS);
		a <<= VHOST_RADIX_BITS;
		node = (trie_node *)(node_ptr & ~0xF);
		node_ptr = *(const unsigned long long *)(&node->val[i]);
	} while ((unsigned char)node_ptr & 0xF);

	v = (vhost_memory_region *)(node_ptr);
	if (likely(v &&
		   v->guest_phys_addr <= addr && v->gpa_end > addr))
		return v;

	return 0;
}


unsigned long long vhost_insert_region(memmap_trie *map, vhost_memory_region *val);

#define VHOST_TRIE_MAX_DEPTH (sizeof(unsigned long long) * 8 / VHOST_RADIX_BITS)
struct vhost_trie_iter {
	int level;
	int cur_idx;
	int idx[VHOST_TRIE_MAX_DEPTH];
	trie_node *nodes[VHOST_TRIE_MAX_DEPTH];
};

#define vhost_memmap_walk_nodes(i, node, child) \
	for (i.level = 0, i.nodes[0] = node, i.idx[0] = 0, \
		child = &node->val[i.idx[i.level]]; \
		((char *)child - (char *)node) >> 4 < NODE_WITDH; \
		node = i.nodes[i.level], \
		child = &node->val[i.idx[i.level]], \
		i.idx[i.level] < NODE_WITDH  && IS_NODE(child) ? \
			(i.idx[i.level]++, i.level++, \
			 i.nodes[i.level] = get_trie_node(child), \
			 i.idx[i.level] = 0) : \
                        (i.idx[i.level]++), \
		i.idx[i.level] == NODE_WITDH ? \
			(i.level -= i.level > 0 ? 1 : 0) : \
			(i.level) \
                )

void dump_map(memmap_trie *map, trie_node_value_t *node_ptr);

#endif
