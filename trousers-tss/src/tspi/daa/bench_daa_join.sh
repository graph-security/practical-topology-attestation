#!/usr/bin/fish
set_color -u green
echo 'start benchmark for daa join'
set_color normal
mkdir perf-daa-join

for i in (seq 1 50)
	sleep 5
	taskset 0x1  ./test_join
	set_color -u blue
	echo 'copying credential'
	set_color normal
	#set ddate (date "+%d_%m_%y_%H_%M_%S")
	cp credential.txt credential_$i.txt
	cp credential_$i.txt perf-daa-join/
	rm -f credential_$i.txt
	set_color -u green
	printf "finished benchmark %s for daa join" "$i"
	set_color normal
end
