.PHONY: run

run:
	cargo build
	./target/debug/vmbox -k /root/code/kvm-host/build/bzImage -i /root/code/kvm-host/build/rootfs.cpio
