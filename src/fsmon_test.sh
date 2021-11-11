#!/bin/bash

daemon="${1}"

PATH=$(pwd)/src:$PATH

"$daemon" $(pwd)/../src/test.conf &
pid=$!


sleep 2
kill -15 %1
wait $!

cat <<!EOF > test2.conf
default_priority = "warning"
default_facility = "local7"
interval = 2
!EOF

"$daemon" test2.conf &
pid=$!
sleep 2

rm -f test2.conf

kill -15 %1
wait $!

exit $?
