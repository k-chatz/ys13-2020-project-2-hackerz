#!/bin/sh
make

PID=ps -eaf | grep picoserver | grep -v grep | awk '{print $2}'

kill -9 $PID

gdb\
-ex 'b httpd.c:58'\
-ex 'b main.c:179'\
-ex 'b main.c:181'\
-ex 'b main.c:194'\
-ex 'b main.c:197'\
-ex 'r'\
-ex 'set follow-fork-mode child'\
-ex 'c'\
-ex 'x/39xw $sp'\
-ex 'x/a $ebp + 4'\
./picoserver
