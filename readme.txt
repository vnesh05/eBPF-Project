1. open ports (./port_opener)
	for p in 8080 8081 8082; do
  		nc -lvnp $p -s 0.0.0.0 &
	done

2. compile eBPF code (./compiler)
	clang -O2 -g -Wall -target bpf -c xdp_portscan.c -o xdp_portscan.o

3. enable eBPF filter (./activate)
	sudo ip link set dev enp0s8 xdp obj xdp_portscan.o sec xdp

4. enable live logging - in terminal 2 on host VM (./live_logger)
	watch -n 1 sudo bpftool map dump name scan_map

5. nmap from Kali Linux 
	sudo nmap -sS -p 8000-8100 -T4 <Target_VM_IP>

6. observe results
	live logging @ terminal 2 in host VM	
		
7. disable eBPF filter (./disable)
	sudo ip link set dev enp0s8 xdp off

