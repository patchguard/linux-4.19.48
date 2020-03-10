/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SGX_H
#define __KVM_X86_SGX_H

#include <linux/kvm_host.h>

#include <linux/capability.h>

int handle_encls_ecreate(struct kvm_vcpu *vcpu);
int handle_encls_einit(struct kvm_vcpu *vcpu,u64* msr_ia32_sgxlepubkeyhash);

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
extern bool __read_mostly enable_sgx;

int handle_encls(struct kvm_vcpu *vcpu);
#else
#define enable_sgx 0
#endif

#endif /* __KVM_X86_SGX_H */


