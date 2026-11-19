/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <elf.h>
#include <errno.h>

#include <bpfilter/btf.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "cgen/rawstubs.h"

static_assert_enum_mapping(_bf_rawstubs, _BF_ELFSTUB_MAX);

#define _free_bf_printk_str_ __attribute__((cleanup(_bf_printk_str_free)))

static int _bf_printk_str_new(struct bf_printk_str **pstr, size_t insn_idx,
                              const char *str)
{
    assert(pstr);
    assert(str);

    *pstr = malloc(sizeof(struct bf_printk_str));
    if (!*pstr)
        return -ENOMEM;

    (*pstr)->insn_idx = insn_idx;
    (*pstr)->str = str;

    return 0;
}

static void _bf_printk_str_free(struct bf_printk_str **pstr)
{
    if (!*pstr)
        return;

    BF_FREEP(pstr);
}

static int _bf_elfstub_prepare(struct bf_elfstub *stub,
                               const struct bf_rawstub *raw)
{
    const Elf64_Ehdr *ehdr = raw->elf;
    Elf64_Shdr *shstrtab;
    Elf64_Shdr *shdrs;
    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *symstrtab = NULL;
    Elf64_Shdr *rodata_shdr = NULL;
    Elf64_Sym *symbols;
    char *sym_strtab;
    size_t sym_count;
    char *strtab;
    int r;

    if (raw->len < sizeof(Elf64_Ehdr))
        return bf_err_r(-EINVAL, "invalid ELF header (wrong header size)");

    // Check ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return bf_err_r(-EINVAL, "invalid ELF header (wrong magic number)");

    // Ensure 64-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return bf_err_r(-ENOTSUP, "only 64-bit ELF is supported");

    // Get section header table
    if (ehdr->e_shoff >= raw->len || ehdr->e_shentsize != sizeof(Elf64_Shdr))
        return bf_err_r(-EINVAL, "invalid section header table");

    if (ehdr->e_shstrndx >= ehdr->e_shnum)
        return bf_err_r(-EINVAL, "invalid string table index");

    shdrs = (Elf64_Shdr *)(raw->elf + ehdr->e_shoff);
    shstrtab = &shdrs[ehdr->e_shstrndx];
    if (shstrtab->sh_offset >= raw->len)
        return bf_err_r(-EINVAL, "invalid string table offset");

    strtab = (char *)(raw->elf + shstrtab->sh_offset);

    // Find .text section
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (!bf_streq(&strtab[shdrs[i].sh_name], ".text"))
            continue;

        if (shdrs[i].sh_offset + shdrs[i].sh_size > raw->len)
            return bf_err_r(-EINVAL, "invalid .text section");

        stub->insns = malloc(shdrs[i].sh_size);
        if (!stub->insns)
            return -ENOMEM;

        memcpy(stub->insns, raw->elf + shdrs[i].sh_offset, shdrs[i].sh_size);
        stub->ninsns = shdrs[i].sh_size / sizeof(struct bpf_insn);
        break;
    }

    if (!stub->insns)
        return bf_err_r(-ENOENT, ".text section not found");

    // Find symbol table and its string table
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = &shdrs[i];
            if (shdrs[i].sh_link < ehdr->e_shnum)
                symstrtab = &shdrs[shdrs[i].sh_link];
        } else if (bf_streq(&strtab[shdrs[i].sh_name], ".rodata")) {
            rodata_shdr = &shdrs[i];
        }
    }

    if (!symtab || !symstrtab)
        return bf_err_r(-ENOENT, "symbol table not found");

    symbols = (Elf64_Sym *)(raw->elf + symtab->sh_offset);
    sym_strtab = (char *)(raw->elf + symstrtab->sh_offset);
    sym_count = symtab->sh_size / sizeof(Elf64_Sym);

    // Process REL relocation sections
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_REL)
            continue;

        /* Check if this relocation section applies to .text. sh_info contains
         * the section index this relocation applies to. */
        if (shdrs[i].sh_info != 0 &&
            !bf_streq(&strtab[shdrs[shdrs[i].sh_info].sh_name], ".text"))
            continue;

        // REL relocations (no addend)
        Elf64_Rel *rels = (Elf64_Rel *)(raw->elf + shdrs[i].sh_offset);
        size_t rel_count = shdrs[i].sh_size / sizeof(Elf64_Rel);

        for (size_t j = 0; j < rel_count; j++) {
            uint32_t type = ELF64_R_TYPE(rels[j].r_info);
            uint32_t sym_idx = ELF64_R_SYM(rels[j].r_info);

            if (type == R_BPF_64_32 && sym_idx < sym_count) {
                uint32_t name_idx = symbols[sym_idx].st_name;
                if (name_idx < symstrtab->sh_size) {
                    const char *name = &sym_strtab[name_idx];
                    int id = bf_btf_get_id(name);
                    if (id < 0)
                        return bf_err_r(id, "function %s not found", name);

                    size_t idx = rels[j].r_offset / 8;
                    stub->insns[idx] = ((struct bpf_insn) {
                        .code = BPF_JMP | BPF_CALL,
                        .dst_reg = 0,
                        .src_reg = BPF_PSEUDO_KFUNC_CALL,
                        .off = 0,
                        .imm = id,
                    });

                    bf_dbg("updated stub to call '%s' from instruction %lu",
                           name, idx);
                }
            } else if (type == R_BPF_64_64 && rodata_shdr) {
                _free_bf_printk_str_ struct bf_printk_str *pstr = NULL;
                size_t insn_idx = rels[j].r_offset / 8;
                size_t str_offset = stub->insns[insn_idx].imm;
                const char *str =
                    raw->elf + rodata_shdr->sh_offset + str_offset;

                r = _bf_printk_str_new(&pstr, insn_idx, str);
                if (r)
                    return bf_err_r(r, "failed to create printk_str");

                r = bf_list_add_tail(&stub->strs, pstr);
                if (r)
                    return bf_err_r(r, "failed to add printk_str to elfstub");

                TAKE_PTR(pstr);
            }
        }
    }

    return 0;
}

int bf_elfstub_new(struct bf_elfstub **stub, enum bf_elfstub_id id)
{
    _free_bf_elfstub_ struct bf_elfstub *_stub = NULL;
    int r;

    assert(stub);

    _stub = calloc(1, sizeof(*_stub));
    if (!_stub)
        return -ENOMEM;

    _stub->strs = bf_list_default(_bf_printk_str_free, NULL);

    r = _bf_elfstub_prepare(_stub, &_bf_rawstubs[id]);
    if (r)
        return r;

    *stub = TAKE_PTR(_stub);

    return 0;
}

void bf_elfstub_free(struct bf_elfstub **stub)
{
    assert(stub);

    if (!*stub)
        return;

    bf_list_clean(&(*stub)->strs);
    BF_FREEP(&(*stub)->insns);
    BF_FREEP(stub);
}
