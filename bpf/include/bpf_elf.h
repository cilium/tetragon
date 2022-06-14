/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_ELF__
#define __BPF_ELF__

/* Note:
 *
 * Below ELF section names and bpf_elf_map structure definition
 * are not (!) kernel ABI. It's rather a "contract" between the
 * application and the BPF loader in tc. For compatibility, the
 * section names should stay as-is. Introduction of aliases, if
 * needed, are a possibility, though.
 */

/* ELF section names, etc */
#define ELF_SECTION_LICENSE    "license"
#define ELF_SECTION_MAPS       "maps"
#define ELF_SECTION_PROG       "prog"
#define ELF_SECTION_CLASSIFIER "classifier"
#define ELF_SECTION_ACTION     "action"

#define ELF_MAX_MAPS	    64
#define ELF_MAX_LICENSE_LEN 128

/* Object pinning settings */
#define PIN_NONE      0
#define PIN_OBJECT_NS 1
#define PIN_GLOBAL_NS 2

/* ELF map definition */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)                         \
	struct ____btf_map_##name {                                            \
		type_key key;                                                  \
		type_val value;                                                \
	};                                                                     \
	struct ____btf_map_##name                                              \
		__attribute__((section(".maps." #name), used))                 \
		____btf_map_##name = {}

#endif /* __BPF_ELF__ */
