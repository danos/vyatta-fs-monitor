#!/bin/bash

daemon="${1}"

PATH=$(pwd)/src:$PATH

"$daemon" test.conf
pid=$!

sleep 2
kill -15 %1
wait $!

exit $?
