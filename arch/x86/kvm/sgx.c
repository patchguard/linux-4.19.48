// SPDX-License-Identifier: GPL-2.0

#include <asm/sgx.h>
#include <asm/sgx_arch.h>

#include <asm/vmx.h>
#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "sgx.h"
#include "x86.h"

bool __read_mostly enable_sgx = 1;
module_param_named(sgx, enable_sgx, bool, 0444);

/*
 * ENCLS's memory operands use a fixed segment (DS) and a fixed
 * address size based on the mode.  Related prefixes are ignored.
 */
static int sgx_get_encls_gva(struct kvm_vcpu *vcpu, unsigned long offset,
			     int size, int alignment, gva_t *gva)
{
	struct kvm_segment s;
	bool fault;

	kvm_get_segment(vcpu, &s, VCPU_SREG_DS);

	*gva = s.base + offset;

	if (!IS_ALIGNED(*gva, alignment)) {
		fault = true;
	} else if (is_long_mode(vcpu)) {
		fault = is_noncanonical_address(*gva, vcpu);
	} else {
		*gva &= 0xffffffff;
		fault = (s.unusable) ||
			(s.type != 2 && s.type != 3) ||
			(*gva > s.limit) ||
			((s.base != 0 || s.limit != 0xffffffff) &&
			(((u64)*gva + size - 1) > s.limit + 1));
	}
	if (fault)
		kvm_inject_gp(vcpu, 0);
	return fault ? -EINVAL : 0;
}

static int sgx_read_gva(struct kvm_vcpu *vcpu, gva_t gva, void *data,
			 unsigned int size)
{
	struct x86_exception ex;

	if (kvm_read_guest_virt(vcpu, gva, data, size, &ex)) {
		kvm_propagate_page_fault(vcpu, &ex);
		return -EFAULT;
	}
	return 0;
}

static int sgx_read_hva(struct kvm_vcpu *vcpu, unsigned long hva, void *data,
			unsigned int size)
{
	if (__copy_from_user(data, (void __user *)hva, size)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = hva;
		vcpu->run->internal.data[1] = size;
		return -EFAULT;
	}
	return 0;
}

static int sgx_gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva, bool write,
			  unsigned long *hva)
{
	struct x86_exception ex;
	gpa_t gpa;

	if (write)
		gpa = kvm_mmu_gva_to_gpa_write(vcpu, gva, &ex);
	else
		gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, &ex);

	if (gpa == UNMAPPED_GVA) {
		kvm_propagate_page_fault(vcpu, &ex);
		return -EFAULT;
	}

	*hva = kvm_vcpu_gfn_to_hva(vcpu, PFN_DOWN(gpa));
	if (kvm_is_error_hva(*hva)) {
		ex.vector = PF_VECTOR;
		ex.error_code = PFERR_PRESENT_MASK;
		if (write)
			ex.error_code |= PFERR_WRITE_MASK;
		ex.address = gva;
		ex.error_code_valid = true;
		ex.nested_page_fault = false;
		kvm_propagate_page_fault(vcpu, &ex);
		return -EFAULT;
	}

	return 0;
}

static inline unsigned long kvm_rax_read(struct kvm_vcpu *vcpu)
{
	return kvm_register_read(vcpu, VCPU_REGS_RAX);
}

static inline unsigned long kvm_rbx_read(struct kvm_vcpu *vcpu)
{
        return kvm_register_read(vcpu, VCPU_REGS_RBX);
}

static inline unsigned long kvm_rcx_read(struct kvm_vcpu *vcpu)
{
        return kvm_register_read(vcpu, VCPU_REGS_RCX);
}

static inline unsigned long kvm_rdx_read(struct kvm_vcpu *vcpu)
{
        return kvm_register_read(vcpu, VCPU_REGS_RDX);
}

static inline void kvm_rax_write(struct kvm_vcpu *vcpu, unsigned long val)
{
	kvm_register_write(vcpu, VCPU_REGS_RAX, val);
}

static inline void kvm_rbx_write(struct kvm_vcpu *vcpu, unsigned long val)
{
        kvm_register_write(vcpu, VCPU_REGS_RBX, val);
}

static inline void kvm_rcx_write(struct kvm_vcpu *vcpu, unsigned long val)
{
        kvm_register_write(vcpu, VCPU_REGS_RCX, val);
}

static inline void kvm_rdx_write(struct kvm_vcpu *vcpu, unsigned long val)
{
        kvm_register_write(vcpu, VCPU_REGS_RDX, val);
}

static int sgx_encls_postamble(struct kvm_vcpu *vcpu, int ret, int trapnr,
			       gva_t gva)
{
	struct x86_exception ex;
	unsigned long rflags;

	if (ret == -EFAULT)
		goto handle_fault;

	rflags = kvm_get_rflags(vcpu) & ~(X86_EFLAGS_CF | X86_EFLAGS_PF |
					  X86_EFLAGS_AF | X86_EFLAGS_SF |
					  X86_EFLAGS_OF);
	if (ret)
		rflags |= X86_EFLAGS_ZF;
	else
		rflags &= ~X86_EFLAGS_ZF;
	kvm_set_rflags(vcpu, rflags);

	kvm_rax_write(vcpu, ret);
	return kvm_skip_emulated_instruction(vcpu);

handle_fault:
	/*
	 * A non-EPCM #PF indicates a bad userspace HVA.  This *should* check
	 * for PFEC.SGX and not assume any #PF on SGX2 originated in the EPC,
	 * but the error code isn't (yet) plumbed through the ENCLS helpers.
	 */
	if (trapnr == PF_VECTOR && !boot_cpu_has(X86_FEATURE_SGX2)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return 0;
	}

	/*
	 * If the guest thinks it's running on SGX2 hardware, inject an SGX
	 * #PF if the fault matches an EPCM fault signature (#GP on SGX1,
	 * #PF on SGX2).  The assumption is that EPCM faults are much more
	 * likely than a bad userspace address.
	 */
	if ((trapnr == PF_VECTOR || !boot_cpu_has(X86_FEATURE_SGX2)) &&
	    guest_cpuid_has(vcpu, X86_FEATURE_SGX2)) {
		ex.vector = PF_VECTOR;
		ex.error_code = PFERR_PRESENT_MASK | PFERR_WRITE_MASK |
				PFERR_SGX_MASK;
		ex.address = gva;
		ex.error_code_valid = true;
		ex.nested_page_fault = false;
		kvm_inject_page_fault(vcpu, &ex);
	} else {
		kvm_inject_gp(vcpu, 0);
	}
	return 1;
}

int handle_encls_ecreate(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *sgx_12_0, *sgx_12_1;
	unsigned long a_hva, m_hva, x_hva, secs_hva;
	struct sgx_pageinfo pageinfo;
	gva_t pageinfo_gva, secs_gva;
	u64 attributes, xfrm;
	int ret, trapnr;
	u32 miscselect;

	sgx_12_0 = kvm_find_cpuid_entry(vcpu, 0x12, 0);
	sgx_12_1 = kvm_find_cpuid_entry(vcpu, 0x12, 1);
	if (!sgx_12_0 || !sgx_12_1) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (sgx_get_encls_gva(vcpu, kvm_rbx_read(vcpu), 32, 32, &pageinfo_gva) ||
	    sgx_get_encls_gva(vcpu, kvm_rcx_read(vcpu), 4096, 4096, &secs_gva))
		return 1;

	/*
	 * Copy the PAGEINFO to local memory, its pointers need to be
	 * translated, i.e. we need to do a deep copy/translate.
	 */
	if (sgx_read_gva(vcpu, pageinfo_gva, &pageinfo, sizeof(pageinfo)))
		return 1;

	/* Translate the SECINFO, SOURCE and SECS pointers from GVA to HVA. */
	if (sgx_gva_to_hva(vcpu, pageinfo.metadata, false,
			   (unsigned long *)&pageinfo.metadata) ||
	    sgx_gva_to_hva(vcpu, pageinfo.contents, false,
			   (unsigned long *)&pageinfo.contents) ||
	    sgx_gva_to_hva(vcpu, secs_gva, true, &secs_hva))
		return 1;

	m_hva = pageinfo.contents + offsetof(struct sgx_secs, miscselect);
	a_hva = pageinfo.contents + offsetof(struct sgx_secs, attributes);
	x_hva = pageinfo.contents + offsetof(struct sgx_secs, xfrm);

	/* Exit to userspace if copying from a host userspace address fails. */
	if (sgx_read_hva(vcpu, m_hva, &miscselect, sizeof(miscselect)) ||
	    sgx_read_hva(vcpu, a_hva, &attributes, sizeof(attributes)) ||
	    sgx_read_hva(vcpu, x_hva, &xfrm, sizeof(xfrm)))
		return 0;

	/* Enforce restriction of access to the PROVISIONKEY. */
	if (!vcpu->kvm->arch.sgx_provisioning_allowed &&
	    (attributes & SGX_ATTR_PROVISIONKEY)) {
		if (sgx_12_1->eax & SGX_ATTR_PROVISIONKEY)
			pr_warn_once("KVM: SGX PROVISIONKEY advertised but not allowed\n");
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	/* Enforce CPUID restrictions on MISCSELECT, ATTRIBUTES and XFRM. */
	if ((u32)miscselect & ~sgx_12_0->ebx ||
	    (u32)attributes & ~sgx_12_1->eax ||
	    (u32)(attributes >> 32) & ~sgx_12_1->ebx ||
	    (u32)xfrm & ~sgx_12_1->ecx ||
	    (u32)(xfrm >> 32) & ~sgx_12_1->edx) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	ret = sgx_virt_ecreate(&pageinfo, (void __user *)secs_hva, &trapnr);

	return sgx_encls_postamble(vcpu, ret, trapnr, secs_gva);
}

int handle_encls_einit(struct kvm_vcpu *vcpu,u64* msr_ia32_sgxlepubkeyhash)
{
	unsigned long sig_hva, secs_hva, token_hva;
	gva_t sig_gva, secs_gva, token_gva;
	int ret, trapnr;

	if (sgx_get_encls_gva(vcpu, kvm_rbx_read(vcpu), 1808, 4096, &sig_gva) ||
	    sgx_get_encls_gva(vcpu, kvm_rcx_read(vcpu), 4096, 4096, &secs_gva) ||
	    sgx_get_encls_gva(vcpu, kvm_rdx_read(vcpu), 304, 512, &token_gva))
		return 1;

	if (sgx_gva_to_hva(vcpu, sig_gva, false, &sig_hva) ||
	    sgx_gva_to_hva(vcpu, secs_gva, true, &secs_hva) ||
	    sgx_gva_to_hva(vcpu, token_gva, false, &token_hva))
		return 1;

	ret = sgx_virt_einit((void __user *)sig_hva, (void __user *)token_hva,
			     (void __user *)secs_hva,
			     msr_ia32_sgxlepubkeyhash, &trapnr);

	return sgx_encls_postamble(vcpu, ret, trapnr, secs_hva);
}

