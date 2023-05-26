#!/usr/bin/fish
set_color -u green
echo 'start benchmark for daa sign'
set_color normal
mkdir perf-daa-sign

for i in (seq 1 50)
	sleep 2
	taskset 0x1  ./test_sign
end
set_color -u blue
echo 'copying signature'
set_color normal
set ddate (date "+%d_%m_%y_%H_%M_%S")
cp credential.txt credential_$ddate.txt
cp credential_$ddate.txt perf-daa-sign/
rm -f credential_$ddate.txt
set_color -u green
echo 'finished benchmark for daa sign'
set_color normal
