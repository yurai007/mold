#include "mold.h"
#include <immintrin.h>
#include <x86intrin.h>

namespace mold::elf {

using E = X86_64;

// The compact PLT format is used when `-z now` is given. If the flag
// is given, all PLT symbols are resolved eagerly on startup, so we
// can omit code for lazy symbol resolution from PLT in that case.
static void write_compact_plt(Context<E> &ctx) {
  u8 *buf = ctx.buf + ctx.plt->shdr.sh_offset;

  static const u8 data[] = {
    0xff, 0x25, 0, 0, 0, 0, // jmp *foo@GOT
    0x66, 0x90,             // nop
  };

  for (Symbol<E> *sym : ctx.plt->symbols) {
    u8 *ent = buf + sym->get_plt_idx(ctx) * ctx.plt_size;
    memcpy(ent, data, sizeof(data));
    *(ul32 *)(ent + 2) = sym->get_gotplt_addr(ctx) - sym->get_plt_addr(ctx) - 6;
  }
}

// The IBTPLT is a security-enhanced version of the regular PLT.
// It uses Indirect Branch Tracking (IBT) feature which is part of
// Intel Control-Flow Enforcement (CET).
//
// Note that our IBTPLT instruction sequence is different from the one
// used in GNU ld. GNU's IBTPLT implementation uses two separate
// sections (.plt and .plt.sec) in which one PLT entry takes 32 bytes
// in total. Our PLT consists of just .plt and each entry is 16 bytes
// long.
//
// Our PLT entry clobbers r11, but that's fine because the resolver
// function (_dl_runtime_resolve) does not preserve r11 anyway.
static void write_ibtplt(Context<E> &ctx) {
  u8 *buf = ctx.buf + ctx.plt->shdr.sh_offset;

  // Write PLT header
  static const u8 plt0[] = {
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x41, 0x53,             // push %r11
    0xff, 0x35, 0, 0, 0, 0, // push GOTPLT+8(%rip)
    0xff, 0x25, 0, 0, 0, 0, // jmp *GOTPLT+16(%rip)
    0x0f, 0x1f, 0x40, 0x00, // nop
    0x0f, 0x1f, 0x40, 0x00, // nop
    0x0f, 0x1f, 0x40, 0x00, // nop
    0x66, 0x90,             // nop
  };

  memcpy(buf, plt0, sizeof(plt0));
  *(ul32 *)(buf + 8) = ctx.gotplt->shdr.sh_addr - ctx.plt->shdr.sh_addr - 4;
  *(ul32 *)(buf + 14) = ctx.gotplt->shdr.sh_addr - ctx.plt->shdr.sh_addr - 2;

  // Write PLT entries
  i64 relplt_idx = 0;

  static const u8 data[] = {
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x41, 0xbb, 0, 0, 0, 0, // mov $index_in_relplt, %r11d
    0xff, 0x25, 0, 0, 0, 0, // jmp *foo@GOTPLT
  };

  for (Symbol<E> *sym : ctx.plt->symbols) {
    u8 *ent = buf + ctx.plt_hdr_size + sym->get_plt_idx(ctx) * ctx.plt_size;
    memcpy(ent, data, sizeof(data));
    *(ul32 *)(ent + 6) = relplt_idx++;
    *(ul32 *)(ent + 12) = sym->get_gotplt_addr(ctx) - sym->get_plt_addr(ctx) - 16;
  }
}

// The regular PLT.
static void write_plt(Context<E> &ctx) {
  u8 *buf = ctx.buf + ctx.plt->shdr.sh_offset;

  // Write PLT header
  static const u8 plt0[] = {
    0xff, 0x35, 0, 0, 0, 0, // pushq GOTPLT+8(%rip)
    0xff, 0x25, 0, 0, 0, 0, // jmp *GOTPLT+16(%rip)
    0x0f, 0x1f, 0x40, 0x00, // nop
  };

  memcpy(buf, plt0, sizeof(plt0));
  *(ul32 *)(buf + 2) = ctx.gotplt->shdr.sh_addr - ctx.plt->shdr.sh_addr + 2;
  *(ul32 *)(buf + 8) = ctx.gotplt->shdr.sh_addr - ctx.plt->shdr.sh_addr + 4;

  // Write PLT entries
  i64 relplt_idx = 0;

  static const u8 data[] = {
    0xff, 0x25, 0, 0, 0, 0, // jmp   *foo@GOTPLT
    0x68, 0,    0, 0, 0,    // push  $index_in_relplt
    0xe9, 0,    0, 0, 0,    // jmp   PLT[0]
  };

  for (Symbol<E> *sym : ctx.plt->symbols) {
    u8 *ent = buf + ctx.plt_hdr_size + sym->get_plt_idx(ctx) * ctx.plt_size;
    memcpy(ent, data, sizeof(data));
    *(ul32 *)(ent + 2) = sym->get_gotplt_addr(ctx) - sym->get_plt_addr(ctx) - 6;
    *(ul32 *)(ent + 7) = relplt_idx++;
    *(ul32 *)(ent + 12) = ctx.plt->shdr.sh_addr - sym->get_plt_addr(ctx) - 16;
  }
}

template <>
void PltSection<E>::copy_buf(Context<E> &ctx) {
  if (ctx.arg.z_now)
    write_compact_plt(ctx);
  else if (ctx.arg.z_ibtplt)
    write_ibtplt(ctx);
  else
    write_plt(ctx);
}

template <>
void PltGotSection<E>::copy_buf(Context<E> &ctx) {
  u8 *buf = ctx.buf + this->shdr.sh_offset;

  static const u8 data[] = {
    0xff, 0x25, 0, 0, 0, 0, // jmp *foo@GOT
    0x66, 0x90,             // nop
  };

  for (Symbol<E> *sym : symbols) {
    u8 *ent = buf + sym->get_pltgot_idx(ctx) * X86_64::pltgot_size;
    memcpy(ent, data, sizeof(data));
    *(ul32 *)(ent + 2) = sym->get_got_addr(ctx) - sym->get_plt_addr(ctx) - 6;
  }
}

template <>
void EhFrameSection<E>::apply_reloc(Context<E> &ctx, ElfRel<E> &rel,
                                    u64 offset, u64 val) {
  u8 *loc = ctx.buf + this->shdr.sh_offset + offset;

  switch (rel.r_type) {
  case R_X86_64_NONE:
    return;
  case R_X86_64_32:
    *(ul32 *)loc = val;
    return;
  case R_X86_64_64:
    *(ul64 *)loc = val;
    return;
  case R_X86_64_PC32:
    *(ul32 *)loc = val - this->shdr.sh_addr - offset;
    return;
  case R_X86_64_PC64:
    *(ul64 *)loc = val - this->shdr.sh_addr - offset;
    return;
  }
  unreachable();
}

static u32 relax_gotpcrelx(u8 *loc) {
  switch ((loc[0] << 8) | loc[1]) {
  case 0xff15: return 0x90e8; // call *0(%rip) -> call 0
  case 0xff25: return 0x90e9; // jmp  *0(%rip) -> jmp  0
  }
  return 0;
}

static u32 relax_rex_gotpcrelx(u8 *loc) {
  switch ((loc[0] << 16) | (loc[1] << 8) | loc[2]) {
  case 0x488b05: return 0x488d05; // mov 0(%rip), %rax -> lea 0(%rip), %rax
  case 0x488b0d: return 0x488d0d; // mov 0(%rip), %rcx -> lea 0(%rip), %rcx
  case 0x488b15: return 0x488d15; // mov 0(%rip), %rdx -> lea 0(%rip), %rdx
  case 0x488b1d: return 0x488d1d; // mov 0(%rip), %rbx -> lea 0(%rip), %rbx
  case 0x488b25: return 0x488d25; // mov 0(%rip), %rsp -> lea 0(%rip), %rsp
  case 0x488b2d: return 0x488d2d; // mov 0(%rip), %rbp -> lea 0(%rip), %rbp
  case 0x488b35: return 0x488d35; // mov 0(%rip), %rsi -> lea 0(%rip), %rsi
  case 0x488b3d: return 0x488d3d; // mov 0(%rip), %rdi -> lea 0(%rip), %rdi
  case 0x4c8b05: return 0x4c8d05; // mov 0(%rip), %r8  -> lea 0(%rip), %r8
  case 0x4c8b0d: return 0x4c8d0d; // mov 0(%rip), %r9  -> lea 0(%rip), %r9
  case 0x4c8b15: return 0x4c8d15; // mov 0(%rip), %r10 -> lea 0(%rip), %r10
  case 0x4c8b1d: return 0x4c8d1d; // mov 0(%rip), %r11 -> lea 0(%rip), %r11
  case 0x4c8b25: return 0x4c8d25; // mov 0(%rip), %r12 -> lea 0(%rip), %r12
  case 0x4c8b2d: return 0x4c8d2d; // mov 0(%rip), %r13 -> lea 0(%rip), %r13
  case 0x4c8b35: return 0x4c8d35; // mov 0(%rip), %r14 -> lea 0(%rip), %r14
  case 0x4c8b3d: return 0x4c8d3d; // mov 0(%rip), %r15 -> lea 0(%rip), %r15
  }
  return 0;
}

static u32 relax_gottpoff(u8 *loc) {
  switch ((loc[0] << 16) | (loc[1] << 8) | loc[2]) {
  case 0x488b05: return 0x48c7c0; // mov 0(%rip), %rax -> mov $0, %rax
  case 0x488b0d: return 0x48c7c1; // mov 0(%rip), %rcx -> mov $0, %rcx
  case 0x488b15: return 0x48c7c2; // mov 0(%rip), %rdx -> mov $0, %rdx
  case 0x488b1d: return 0x48c7c3; // mov 0(%rip), %rbx -> mov $0, %rbx
  case 0x488b25: return 0x48c7c4; // mov 0(%rip), %rsp -> mov $0, %rsp
  case 0x488b2d: return 0x48c7c5; // mov 0(%rip), %rbp -> mov $0, %rbp
  case 0x488b35: return 0x48c7c6; // mov 0(%rip), %rsi -> mov $0, %rsi
  case 0x488b3d: return 0x48c7c7; // mov 0(%rip), %rdi -> mov $0, %rdi
  case 0x4c8b05: return 0x49c7c0; // mov 0(%rip), %r8  -> mov $0, %r8
  case 0x4c8b0d: return 0x49c7c1; // mov 0(%rip), %r9  -> mov $0, %r9
  case 0x4c8b15: return 0x49c7c2; // mov 0(%rip), %r10 -> mov $0, %r10
  case 0x4c8b1d: return 0x49c7c3; // mov 0(%rip), %r11 -> mov $0, %r11
  case 0x4c8b25: return 0x49c7c4; // mov 0(%rip), %r12 -> mov $0, %r12
  case 0x4c8b2d: return 0x49c7c5; // mov 0(%rip), %r13 -> mov $0, %r13
  case 0x4c8b35: return 0x49c7c6; // mov 0(%rip), %r14 -> mov $0, %r14
  case 0x4c8b3d: return 0x49c7c7; // mov 0(%rip), %r15 -> mov $0, %r15
  }
  return 0;
}

static u32 relax_gotpc32_tlsdesc(u8 *loc) {
  switch ((loc[0] << 16) | (loc[1] << 8) | loc[2]) {
  case 0x488d05: return 0x48c7c0; // lea 0(%rip), %rax -> mov $0, %rax
  case 0x488d0d: return 0x48c7c1; // lea 0(%rip), %rcx -> mov $0, %rcx
  case 0x488d15: return 0x48c7c2; // lea 0(%rip), %rdx -> mov $0, %rdx
  case 0x488d1d: return 0x48c7c3; // lea 0(%rip), %rbx -> mov $0, %rbx
  case 0x488d25: return 0x48c7c4; // lea 0(%rip), %rsp -> mov $0, %rsp
  case 0x488d2d: return 0x48c7c5; // lea 0(%rip), %rbp -> mov $0, %rbp
  case 0x488d35: return 0x48c7c6; // lea 0(%rip), %rsi -> mov $0, %rsi
  case 0x488d3d: return 0x48c7c7; // lea 0(%rip), %rdi -> mov $0, %rdi
  case 0x4c8d05: return 0x49c7c0; // lea 0(%rip), %r8  -> mov $0, %r8
  case 0x4c8d0d: return 0x49c7c1; // lea 0(%rip), %r9  -> mov $0, %r9
  case 0x4c8d15: return 0x49c7c2; // lea 0(%rip), %r10 -> mov $0, %r10
  case 0x4c8d1d: return 0x49c7c3; // lea 0(%rip), %r11 -> mov $0, %r11
  case 0x4c8d25: return 0x49c7c4; // lea 0(%rip), %r12 -> mov $0, %r12
  case 0x4c8d2d: return 0x49c7c5; // lea 0(%rip), %r13 -> mov $0, %r13
  case 0x4c8d35: return 0x49c7c6; // lea 0(%rip), %r14 -> mov $0, %r14
  case 0x4c8d3d: return 0x49c7c7; // lea 0(%rip), %r15 -> mov $0, %r15
  }
  return 0;
}

// Apply relocations to SHF_ALLOC sections (i.e. sections that are
// mapped to memory at runtime) based on the result of
// scan_relocations().
template <>
void InputSection<E>::apply_reloc_alloc(Context<E> &ctx, u8 *base) {
  ElfRel<E> *dynrel = nullptr;
  std::span<ElfRel<E>> rels = get_rels(ctx);
  i64 frag_idx = 0;

  if (ctx.reldyn)
    dynrel = (ElfRel<E> *)(ctx.buf + ctx.reldyn->shdr.sh_offset +
                                file.reldyn_offset + this->reldyn_offset);

  for (i64 i = 0; i < rels.size(); i++) {
    const ElfRel<E> &rel = rels[i];
    if (rel.r_type == R_X86_64_NONE)
      continue;

    Symbol<E> &sym = *file.symbols[rel.r_sym];
    u8 *loc = base + rel.r_offset;

    const SectionFragmentRef<E> *frag_ref = nullptr;
    if (rel_fragments && rel_fragments[frag_idx].idx == i)
      frag_ref = &rel_fragments[frag_idx++];

    auto overflow_check = [&](i64 val, i64 lo, i64 hi) {
      if (val < lo || hi <= val)
        Error(ctx) << *this << ": relocation " << rel << " against "
                   << sym << " out of range: " << val << " is not in ["
                   << lo << ", " << hi << ")";
    };

    auto write8 = [&](u64 val) {
      overflow_check(val, 0, 1 << 8);
      *loc = val;
    };

    auto write8s = [&](u64 val) {
      overflow_check(val, -(1 << 7), 1 << 7);
      *loc = val;
    };

    auto write16 = [&](u64 val) {
      overflow_check(val, 0, 1 << 16);
      *(ul16 *)loc = val;
    };

    auto write16s = [&](u64 val) {
      overflow_check(val, -(1 << 15), 1 << 15);
      *(ul16 *)loc = val;
    };

    auto write32 = [&](u64 val) {
      overflow_check(val, 0, (i64)1 << 32);
      *(ul32 *)loc = val;
    };

    auto write32s = [&](u64 val) {
      overflow_check(val, -((i64)1 << 31), (i64)1 << 31);
      *(ul32 *)loc = val;
    };

    auto write64 = [&](u64 val) {
      *(ul64 *)loc = val;
    };

#define S   (frag_ref ? frag_ref->frag->get_addr(ctx) : sym.get_addr(ctx))
#define A   (frag_ref ? (u64)frag_ref->addend : (u64)rel.r_addend)
#define P   (output_section->shdr.sh_addr + offset + rel.r_offset)
#define G   (sym.get_got_addr(ctx) - ctx.gotplt->shdr.sh_addr)
#define GOT ctx.gotplt->shdr.sh_addr

    switch (rel.r_type) {
    case R_X86_64_8:
      write8(S + A);
      continue;
    case R_X86_64_16:
      write16(S + A);
      continue;
    case R_X86_64_32:
      write32(S + A);
      continue;
    case R_X86_64_32S:
      write32s(S + A);
      continue;
    case R_X86_64_64:
      if (sym.is_absolute() || !ctx.arg.pic) {
        write64(S + A);
      } else if (sym.is_imported) {
        *dynrel++ = {P, R_X86_64_64, (u32)sym.get_dynsym_idx(ctx), A};
        write64(A);
      } else {
        if (!is_relr_reloc(ctx, rel))
          *dynrel++ = {P, R_X86_64_RELATIVE, 0, (i64)(S + A)};
        write64(S + A);
      }
      continue;
    case R_X86_64_PC8:
      write8s(S + A - P);
      continue;
    case R_X86_64_PC16:
      write16s(S + A - P);
      continue;
    case R_X86_64_PC32:
      write32s(S + A - P);
      continue;
    case R_X86_64_PC64:
      if (sym.is_absolute() || !sym.is_imported || !ctx.arg.shared) {
        write64(S + A - P);
      } else {
        *dynrel++ = {P, R_X86_64_64, (u32)sym.get_dynsym_idx(ctx), A};
        write64(A);
      }
      continue;
    case R_X86_64_PLT32:
      write32s(S + A - P);
      continue;
    case R_X86_64_PLTOFF64:
      write64(S + A - GOT);
      break;
    case R_X86_64_GOT32:
      write32s(G + A);
      continue;
    case R_X86_64_GOT64:
      write64(G + A);
      continue;
    case R_X86_64_GOTOFF64:
      write64(S + A - GOT);
      continue;
    case R_X86_64_GOTPC32:
      write32s(GOT + A - P);
      continue;
    case R_X86_64_GOTPC64:
      write64(GOT + A - P);
      continue;
    case R_X86_64_GOTPCREL:
      write32s(G + GOT + A - P);
      continue;
    case R_X86_64_GOTPCREL64:
      write64(G + GOT + A - P);
      continue;
    case R_X86_64_GOTPCRELX:
      if (sym.get_got_idx(ctx) == -1) {
        u32 insn = relax_gotpcrelx(loc - 2);
        loc[-2] = insn >> 8;
        loc[-1] = insn;
        write32s(S + A - P);
      } else {
        write32s(G + GOT + A - P);
      }
      continue;
    case R_X86_64_REX_GOTPCRELX:
      if (sym.get_got_idx(ctx) == -1) {
        u32 insn = relax_rex_gotpcrelx(loc - 3);
        loc[-3] = insn >> 16;
        loc[-2] = insn >> 8;
        loc[-1] = insn;
        write32s(S + A - P);
      } else {
        write32s(G + GOT + A - P);
      }
      continue;
    case R_X86_64_TLSGD:
      if (sym.get_tlsgd_idx(ctx) == -1) {
        // Relax GD to LE
        i64 val = S - ctx.tls_end + A + 4;
        overflow_check(val, -((i64)1 << 31), (i64)1 << 31);

        switch (rels[i + 1].r_type) {
        case R_X86_64_PLT32:
        case R_X86_64_GOTPCREL:
        case R_X86_64_GOTPCRELX: {
          static const u8 insn[] = {
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0, %rax
            0x48, 0x8d, 0x80, 0,    0,    0, 0,       // lea 0(%rax), %rax
          };
          memcpy(loc - 4, insn, sizeof(insn));
          *(ul32 *)(loc + 8) = val;
          break;
        }
        case R_X86_64_PLTOFF64: {
          static const u8 insn[] = {
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0, %rax
            0x48, 0x8d, 0x80, 0,    0,    0, 0,       // lea 0(%rax), %rax
            0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,       // nop
          };
          memcpy(loc - 3, insn, sizeof(insn));
          *(ul32 *)(loc + 9) = val;
          break;
        }
        default:
          unreachable();
        }

        i++;
      } else {
        write32s(sym.get_tlsgd_addr(ctx) + A - P);
      }
      continue;
    case R_X86_64_TLSLD:
      if (ctx.got->tlsld_idx == -1) {
        // Relax LD to LE
        switch (rels[i + 1].r_type) {
        case R_X86_64_PLT32: {
          static const u8 insn[] = {
            0x66, 0x66, 0x66,                         // (padding)
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0, %rax
          };
          memcpy(loc - 3, insn, sizeof(insn));
          break;
        }
        case R_X86_64_GOTPCREL:
        case R_X86_64_GOTPCRELX: {
          static const u8 insn[] = {
            0x66, 0x66, 0x66,                         // (padding)
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0, %rax
            0x90,                                     // nop
          };
          memcpy(loc - 3, insn, sizeof(insn));
          break;
        }
        case R_X86_64_PLTOFF64: {
          static const u8 insn[] = {
            0x66, 0x66, 0x66,                         // (padding)
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0, %rax
            0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nop
          };
          memcpy(loc - 3, insn, sizeof(insn));
          break;
        }
        default:
          unreachable();
        }

        i++;
      } else {
        write32s(ctx.got->get_tlsld_addr(ctx) + A - P);
      }
      continue;
    case R_X86_64_DTPOFF32:
      if (ctx.arg.relax && !ctx.arg.shared)
        write32s(S + A - ctx.tls_end);
      else
        write32s(S + A - ctx.tls_begin);
      continue;
    case R_X86_64_DTPOFF64:
      if (ctx.arg.relax && !ctx.arg.shared)
        write64(S + A - ctx.tls_end);
      else
        write64(S + A - ctx.tls_begin);
      continue;
    case R_X86_64_TPOFF32:
      write32s(S + A - ctx.tls_end);
      continue;
    case R_X86_64_TPOFF64:
      write64(S + A - ctx.tls_end);
      continue;
    case R_X86_64_GOTTPOFF:
      if (sym.get_gottp_idx(ctx) == -1) {
        u32 insn = relax_gottpoff(loc - 3);
        loc[-3] = insn >> 16;
        loc[-2] = insn >> 8;
        loc[-1] = insn;
        write32s(S + A - ctx.tls_end + 4);
      } else {
        write32s(sym.get_gottp_addr(ctx) + A - P);
      }
      continue;
    case R_X86_64_GOTPC32_TLSDESC:
      if (sym.get_tlsdesc_idx(ctx) == -1) {
        u32 insn = relax_gotpc32_tlsdesc(loc - 3);
        loc[-3] = insn >> 16;
        loc[-2] = insn >> 8;
        loc[-1] = insn;
        write32s(S + A - ctx.tls_end + 4);
      } else {
        write32s(sym.get_tlsdesc_addr(ctx) + A - P);
      }
      continue;
    case R_X86_64_SIZE32:
      write32(sym.esym().st_size + A);
      continue;
    case R_X86_64_SIZE64:
      write64(sym.esym().st_size + A);
      continue;
    case R_X86_64_TLSDESC_CALL:
      if (sym.get_tlsdesc_idx(ctx) == -1) {
        // call *(%rax) -> nop
        loc[0] = 0x66;
        loc[1] = 0x90;
      }
      continue;
    default:
      unreachable();
    }

#undef S
#undef A
#undef P
#undef G
#undef GOT
  }
}

// This function is responsible for applying relocations against
// non-SHF_ALLOC sections (i.e. sections that are not mapped to memory
// at runtime).
//
// Relocations against non-SHF_ALLOC sections are much easier to
// handle than that against SHF_ALLOC sections. It is because, since
// they are not mapped to memory, they don't contain any variable or
// function and never need PLT or GOT. Non-SHF_ALLOC sections are
// mostly debug info sections.
//
// Relocations against non-SHF_ALLOC sections are not scanned by
// scan_relocations.

template <>
void InputSection<E>::apply_reloc_common(u8 *loc, Symbol<E> &sym, const ElfRel<E> &rel, SectionFragment<E> *frag,
                                         i64 addend, Context<E> &ctx) {
  auto overflow_check = [&](i64 val, i64 lo, i64 hi) {
    if (val < lo || hi <= val)
      Error(ctx) << *this << ": relocation " << rel << " against "
                 << sym << " out of range: " << val << " is not in ["
                 << lo << ", " << hi << ")";
  };

  auto write8 = [&](u64 val) {
    overflow_check(val, 0, 1 << 8);
    *loc = val;
  };

  auto write16 = [&](u64 val) {
    overflow_check(val, 0, 1 << 16);
    *(ul16 *)loc = val;
  };

  auto write32 = [&](u64 val) {
    overflow_check(val, 0, (i64)1 << 32);
    *(ul32 *)loc = val;
  };

  auto write32s = [&](u64 val) {
    overflow_check(val, -((i64)1 << 31), (i64)1 << 31);
    *(ul32 *)loc = val;
  };

#define S (frag ? frag->get_addr(ctx) : sym.get_addr(ctx))
#define A (frag ? (u64)addend : (u64)rel.r_addend)

  switch (rel.r_type) {
  case R_X86_64_8:
    write8(S + A);
    break;
  case R_X86_64_16:
    write16(S + A);
    break;
  case R_X86_64_32:
    write32(S + A);
    break;
  case R_X86_64_32S:
    write32s(S + A);
    break;
  case R_X86_64_64:
    if (!frag) {
      if (std::optional<u64> val = get_tombstone(sym)) {
        *(ul64 *)loc = *val;
        break;
      }
    }
    *(ul64 *)loc = S + A;
    break;
  case R_X86_64_DTPOFF32:
    if (std::optional<u64> val = get_tombstone(sym))
      *(ul32 *)loc = *val;
    else
      write32s(S + A - ctx.tls_begin);
    break;
  case R_X86_64_DTPOFF64:
    if (std::optional<u64> val = get_tombstone(sym))
      *(ul64 *)loc = *val;
    else
      *(ul64 *)loc = S + A - ctx.tls_begin;
    break;
  case R_X86_64_SIZE32:
    write32(sym.esym().st_size + A);
    break;
  case R_X86_64_SIZE64:
    *(ul64 *)loc = sym.esym().st_size + A;
    break;
  default:
    Fatal(ctx) << *this << ": invalid relocation for non-allocated sections: "
               << rel;
    break;
  }

#undef S
#undef A
}

using reg = __m256i;
constexpr auto step = 8u;

static reg do_upper_bound_unaligned(const int* __restrict__ base, const int* __restrict__ q, unsigned size) {
  assert(step == 8u && size >= 16 && "Wrong step or too small size");

  const reg query = _mm256_loadu_si256(reinterpret_cast<const reg*>(q));
  reg left_idx = _mm256_set1_epi32(0);
  auto single_step = [&base, &query, &left_idx](unsigned jump){
    reg idx = _mm256_add_epi32(left_idx, _mm256_set1_epi32(jump));
    reg g = _mm256_i32gather_epi32(base, idx, 4);
    reg mask = _mm256_cmpgt_epi32(g, query);
    left_idx = _mm256_blendv_epi8(idx, left_idx, mask);
  };
  unsigned length = size;
  while (length >= 16) {
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
  }
  while (length >= 4) {
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
  }
  while (length >= 2) {
    single_step(length >> 1);
    length = (length & 1) + (length >> 1);
  }
  reg mask_size = _mm256_cmpgt_epi32(_mm256_set1_epi32(size), left_idx);
  reg last_jump =  _mm256_blendv_epi8(_mm256_set1_epi32(0), _mm256_set1_epi32(1), mask_size);
  reg idx = _mm256_add_epi32(left_idx, last_jump);
  reg g = _mm256_i32gather_epi32(base, left_idx, 4);
  reg mask = _mm256_cmpgt_epi32(g, query);
  return _mm256_blendv_epi8(idx, left_idx, mask);
}

static void upper_bound_batched(const int prolog_queue_size, const std::vector<int> &offsets_queue,
                                const std::span<u32> offsets, std::span<u32>::iterator *results) {
  const int *base = reinterpret_cast<const int*>(offsets.data());
  const unsigned size = offsets.size();
  int j = 0;
  while (j + 4*step <= prolog_queue_size) {
    int j0 = j;
    reg res1 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;
    reg res2 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;
    reg res3 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;
    reg res4 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;

    auto tmp1 = reinterpret_cast<const unsigned*>(&res1);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp1[i];
    }
    j0 += step;
    auto tmp2 = reinterpret_cast<const unsigned*>(&res2);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp2[i];
    }
    j0 += step;
    auto tmp3 = reinterpret_cast<const unsigned*>(&res3);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp3[i];
    }
    j0 += step;
    auto tmp4 = reinterpret_cast<const unsigned*>(&res4);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp4[i];
    }
  }

  while (j + 2*step <= prolog_queue_size) {
    int j0 = j;
    reg res1 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;
    reg res2 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;

    auto tmp1 = reinterpret_cast<const unsigned*>(&res1);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp1[i];
    }
    j0 += step;
    auto tmp2 = reinterpret_cast<const unsigned*>(&res2);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp2[i];
    }
  }

  while (j + 1*step <= prolog_queue_size) {
    int j0 = j;
    reg res1 = do_upper_bound_unaligned(base, &offsets_queue[j], size);
    j += step;

    auto tmp1 = reinterpret_cast<const unsigned*>(&res1);
    for (auto i = 0u; i < step; i++) {
      results[j0 + i] = offsets.begin() + tmp1[i];
    }
  }
}

template <>
void InputSection<E>::apply_reloc_nonalloc(Context<E> &ctx, u8 *base) {
  std::span<ElfRel<E>> rels = get_rels(ctx);
#if 0
  assert(rels.size() <= std::numeric_limits<int>::max());
#endif
  unsigned queue_size = 0u;
  std::vector<std::tuple<std::span<u32>, const ElfRel<E>*, MergeableSection<E>*>> data_queue(rels.size());
  std::vector<int> queries_queue(rels.size());
  bool all_equal = true;
  for (i64 i = 0; i < rels.size(); i++) {
    const ElfRel<E> &rel = rels[i];
    if (rel.r_type == R_X86_64_NONE)
      continue;

    Symbol<E> &sym = *file.symbols[rel.r_sym];

    if (!sym.file) {
      report_undef(ctx, file, sym);
      continue;
    }
    assert(!(shdr().sh_flags & SHF_ALLOC));
    u8 *loc = base + rel.r_offset;
    SectionFragment<E> *frag;
    i64 addend;
    bool done = false;

    const ElfSym<E> &esym = file.elf_syms[rel.r_sym];
    if (esym.st_type != STT_SECTION) {
      done = true; frag = nullptr; addend = 0;
    }
    if (!done) {
      std::unique_ptr<MergeableSection<E>> &m =
          file.mergeable_sections[file.get_shndx(esym)];
      if (!m) {
        done = true; frag = nullptr; addend = 0;
      }
      if (!done) {
        // queue for later - slow path
        i64 offset = esym.st_value + get_addend(rel);
        std::span<u32> offsets = m->frag_offsets;
        if (all_equal && (queue_size > 0) && std::get<0>(data_queue[queue_size-1]).data() != offsets.data()) {
          all_equal = false;
        }
#if 0
        assert(offset <= std::numeric_limits<int>::max());
#endif
        queries_queue[queue_size] = static_cast<int>(offset);
        data_queue[queue_size++] = std::make_tuple(offsets, &rel, m.get());
        continue;
      }
    }
    apply_reloc_common(loc, sym, rel, frag, addend, ctx);
  }
  if (data_queue.empty())
    return;

  const std::span<u32> offsets = std::get<std::span<u32>>(data_queue.front());
  if (!all_equal || queue_size < step || offsets.size() < 16) {
    std::vector<i64> idxs(queue_size);
    for (i64 j = 0; j < queue_size; j++) {
      auto &item = data_queue[j];
      i64 offset = queries_queue[j];
      std::span<u32> offsets = std::get<std::span<u32>>(item);
      const ElfRel<E> &rel = *std::get<const ElfRel<E>*>(item);
      auto it = std::upper_bound(offsets.begin(), offsets.end(), offset);
      if (it == offsets.begin())
        Fatal(ctx) << *this << ": bad relocation at " << rel.r_sym;
      idxs[j] = it - 1 - offsets.begin();
    }

    for (i64 j = 0; j < queue_size; j++) {
      i64 idx = idxs[j];
      auto &item = data_queue[j];
      i64 offset = queries_queue[j];
      std::span<u32> offsets = std::get<std::span<u32>>(item);
      const ElfRel<E> &rel = *std::get<const ElfRel<E>*>(item);
      MergeableSection<E>* m = std::get<MergeableSection<E>*>(item);
      SectionFragment<E> * frag = m->fragments[idx];
      i64 addend = offset - offsets[idx];
      u8 *loc = base + rel.r_offset;
      Symbol<E> &sym = *file.symbols[rel.r_sym];
      apply_reloc_common(loc, sym, rel, frag, addend, ctx);
    }
  } else {
    const unsigned prolog_queue_size = (queue_size >> 3)*step;
    std::vector<std::span<u32>::iterator> results(prolog_queue_size);
    upper_bound_batched(prolog_queue_size, queries_queue, offsets, &results[0]);

    i64 j = 0;
    for (; j < prolog_queue_size; j++) {
      auto &item = data_queue[j];
      const ElfRel<E> &rel = *std::get<const ElfRel<E>*>(item);
      MergeableSection<E>* m = std::get<MergeableSection<E>*>(item);

      auto it = results[j];
      if (it == offsets.begin())
        Fatal(ctx) << *this << ": bad relocation at " << rel.r_sym;
      i64 idx = it - 1 - offsets.begin();
      SectionFragment<E> * frag = m->fragments[idx];
      i64 offset = queries_queue[j];
      i64 addend = offset - offsets[idx];
      u8 *loc = base + rel.r_offset;
      Symbol<E> &sym = *file.symbols[rel.r_sym];
      apply_reloc_common(loc, sym, rel, frag, addend, ctx);
    }

    // process remaining epilog
    j = prolog_queue_size;
    std::vector<i64> idxs(queue_size - prolog_queue_size + 1);
    for (; j < queue_size; j++) {
      auto &item = data_queue[j];
      i64 offset = queries_queue[j];
      std::span<u32> offsets = std::get<std::span<u32>>(item);
      const ElfRel<E> &rel = *std::get<const ElfRel<E>*>(item);
      auto it = std::upper_bound(offsets.begin(), offsets.end(), offset);
      if (it == offsets.begin())
        Fatal(ctx) << *this << ": bad relocation at " << rel.r_sym;
      idxs[j - prolog_queue_size] = it - 1 - offsets.begin();
    }
    j = prolog_queue_size;

    for (; j < queue_size; j++) {
      i64 idx = idxs[j - prolog_queue_size];
      auto &item = data_queue[j];
      i64 offset = queries_queue[j];
      std::span<u32> offsets = std::get<std::span<u32>>(item);
      const ElfRel<E> &rel = *std::get<const ElfRel<E>*>(item);
      MergeableSection<E>* m = std::get<MergeableSection<E>*>(item);
      SectionFragment<E> * frag = m->fragments[idx];
      i64 addend = offset - offsets[idx];
      u8 *loc = base + rel.r_offset;
      Symbol<E> &sym = *file.symbols[rel.r_sym];
      apply_reloc_common(loc, sym, rel, frag, addend, ctx);
    }
  }
}

// Linker has to create data structures in an output file to apply
// some type of relocations. For example, if a relocation refers a GOT
// or a PLT entry of a symbol, linker has to create an entry in .got
// or in .plt for that symbol. In order to fix the file layout, we
// need to scan relocations.
template <>
void InputSection<E>::scan_relocations(Context<E> &ctx) {
  assert(shdr().sh_flags & SHF_ALLOC);

  this->reldyn_offset = file.num_dynrel * sizeof(ElfRel<E>);
  std::span<ElfRel<E>> rels = get_rels(ctx);

  // Scan relocations
  for (i64 i = 0; i < rels.size(); i++) {
    const ElfRel<E> &rel = rels[i];
    if (rel.r_type == R_X86_64_NONE)
      continue;

    Symbol<E> &sym = *file.symbols[rel.r_sym];
    u8 *loc = (u8 *)(contents.data() + rel.r_offset);

    if (!sym.file) {
      report_undef(ctx, file, sym);
      continue;
    }

    if (sym.get_type() == STT_GNU_IFUNC) {
      sym.flags |= NEEDS_GOT;
      sym.flags |= NEEDS_PLT;
    }

    switch (rel.r_type) {
    case R_X86_64_8:
    case R_X86_64_16:
    case R_X86_64_32:
    case R_X86_64_32S: {
      // Dynamic linker does not support 8, 16 or 32-bit dynamic
      // relocations for these types of relocations. We report an
      // error if we cannot relocate them even at load-time.
      Action table[][4] = {
        // Absolute  Local  Imported data  Imported code
        {  NONE,     ERROR, ERROR,         ERROR },      // DSO
        {  NONE,     ERROR, ERROR,         ERROR },      // PIE
        {  NONE,     NONE,  COPYREL,       CPLT  },      // PDE
      };
      dispatch(ctx, table, i, rel, sym);
      break;
    }
    case R_X86_64_64: {
      // Unlike the above, we can use R_X86_64_RELATIVE and R_86_64_64
      // relocations.
      Action table[][4] = {
        // Absolute  Local    Imported data  Imported code
        {  NONE,     BASEREL, DYNREL,        DYNREL },     // DSO
        {  NONE,     BASEREL, DYNREL,        DYNREL },     // PIE
        {  NONE,     NONE,    COPYREL,       CPLT   },     // PDE
      };
      dispatch(ctx, table, i, rel, sym);
      break;
    }
    case R_X86_64_PC8:
    case R_X86_64_PC16:
    case R_X86_64_PC32: {
      Action table[][4] = {
        // Absolute  Local  Imported data  Imported code
        {  ERROR,    NONE,  ERROR,         ERROR },      // DSO
        {  ERROR,    NONE,  COPYREL,       PLT   },      // PIE
        {  NONE,     NONE,  COPYREL,       PLT   },      // PDE
      };
      dispatch(ctx, table, i, rel, sym);
      break;
    }
    case R_X86_64_PC64: {
      Action table[][4] = {
        // Absolute  Local  Imported data  Imported code
        {  ERROR,    NONE,  DYNREL,        DYNREL },     // DSO
        {  ERROR,    NONE,  COPYREL,       PLT    },     // PIE
        {  NONE,     NONE,  COPYREL,       PLT    },     // PDE
      };
      dispatch(ctx, table, i, rel, sym);
      break;
    }
    case R_X86_64_GOT32:
    case R_X86_64_GOT64:
    case R_X86_64_GOTPC32:
    case R_X86_64_GOTPC64:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCREL64:
      sym.flags |= NEEDS_GOT;
      break;
    case R_X86_64_GOTPCRELX: {
      if (rel.r_addend != -4)
        Fatal(ctx) << *this << ": bad r_addend for R_X86_64_GOTPCRELX";

      bool do_relax = ctx.arg.relax && !sym.is_imported &&
                      sym.is_relative() && relax_gotpcrelx(loc - 2);
      if (!do_relax)
        sym.flags |= NEEDS_GOT;
      break;
    }
    case R_X86_64_REX_GOTPCRELX: {
      if (rel.r_addend != -4)
        Fatal(ctx) << *this << ": bad r_addend for R_X86_64_REX_GOTPCRELX";

      bool do_relax = ctx.arg.relax && !sym.is_imported &&
                      sym.is_relative() && relax_rex_gotpcrelx(loc - 3);
      if (!do_relax)
        sym.flags |= NEEDS_GOT;
      break;
    }
    case R_X86_64_PLT32:
    case R_X86_64_PLTOFF64: {
      Action table[][4] = {
        // Absolute  Local  Imported data  Imported code
        {  NONE,     NONE,  PLT,           PLT    },     // DSO
        {  NONE,     NONE,  PLT,           PLT    },     // PIE
        {  NONE,     NONE,  PLT,           PLT    },     // PDE
      };
      dispatch(ctx, table, i, rel, sym);
      break;
    }
    case R_X86_64_TLSGD: {
      if (i + 1 == rels.size())
        Fatal(ctx) << *this << ": TLSGD reloc must be followed by PLT or GOTPCREL";

      if (u32 ty = rels[i + 1].r_type;
          ty != R_X86_64_PLT32 && ty != R_X86_64_PLTOFF64 &&
          ty != R_X86_64_GOTPCREL && ty != R_X86_64_GOTPCRELX)
        Fatal(ctx) << *this << ": TLSGD reloc must be followed by PLT or GOTPCREL";

      if (ctx.arg.relax && !ctx.arg.shared && !sym.is_imported)
        i++;
      else
        sym.flags |= NEEDS_TLSGD;
      break;
    }
    case R_X86_64_TLSLD: {
      if (i + 1 == rels.size())
        Fatal(ctx) << *this << ": TLSLD reloc must be followed by PLT or GOTPCREL";

      if (u32 ty = rels[i + 1].r_type;
          ty != R_X86_64_PLT32 && ty != R_X86_64_PLTOFF64 &&
          ty != R_X86_64_GOTPCREL && ty != R_X86_64_GOTPCRELX)
        Fatal(ctx) << *this << ": TLSLD reloc must be followed by PLT or GOTPCREL";

      if (ctx.arg.relax && !ctx.arg.shared)
        i++;
      else
        ctx.needs_tlsld = true;
      break;
    }
    case R_X86_64_GOTTPOFF: {
      ctx.has_gottp_rel = true;

      bool do_relax = ctx.arg.relax && !ctx.arg.shared &&
                      !sym.is_imported && relax_gottpoff(loc - 3);
      if (!do_relax)
        sym.flags |= NEEDS_GOTTP;
      break;
    }
    case R_X86_64_GOTPC32_TLSDESC: {
      if (relax_gotpc32_tlsdesc(loc - 3) == 0)
        Fatal(ctx) << *this << ": GOTPC32_TLSDESC relocation is used"
                   << " against an invalid code sequence";

      bool do_relax = ctx.relax_tlsdesc && !sym.is_imported;
      if (!do_relax)
        sym.flags |= NEEDS_TLSDESC;
      break;
    }
    case R_X86_64_GOTOFF64:
    case R_X86_64_DTPOFF32:
    case R_X86_64_DTPOFF64:
    case R_X86_64_TPOFF32:
    case R_X86_64_TPOFF64:
    case R_X86_64_SIZE32:
    case R_X86_64_SIZE64:
    case R_X86_64_TLSDESC_CALL:
      break;
    default:
      Error(ctx) << *this << ": unknown relocation: " << rel;
    }
  }
}

} // namespace mold::elf
