#! /bin/sh

../src/gs-transfer -s DkGDq3MU9BKfVg3DkobAHT test*.dat test*.sdat
sleep 1
../src/gs-transfer -s DkGDq3MU9BKfVg3DkobAHT - <test-1.pipe

