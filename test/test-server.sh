#! /bin/sh

mk_dummy()
{
	[ -f "$1" ] || dd bs=1024 count=$2 if=/dev/urandom of="$1" 2>/dev/null
}

#mk_dummy test50MB.dat 51200
mk_dummy test50k.dat 50
mk_dummy test50k-restart.dat 50
mk_dummy test8k-alreadythere.dat 8
mk_dummy test1k-1.dat 1
mk_dummy test1k-2.dat 1
mk_dummy test1k-3.dat 1
mk_dummy test1k-4.dat 1
mk_dummy test-symlink-1.sdat 1
mk_dummy test-symlink-2.sdat 8
mk_dummy test-1.pipe 25
mk_dummy test0k.dat 0
fname="testodVeryLongFileNameThatIsToLongToBeDispalyedBut-[]_canBetransfered.dat"
[ -f "$fname" ] || dd bs=1 count=31337 if=/dev/urandom of="$fname" 2>/dev/null

md5 *.dat

[ -d server ] && rm -rf server
mkdir -p server
cd server
dd bs=999 count=12 if="../test50k-restart.dat" of="test50k-restart.dat" 2>/dev/null
cp ../test8k-alreadythere.dat .
# Test non-existing sym link
ln -s /tmp/test-symlink-1.sdat test-symlink-1.sdat

# Test existing sym link
fname=/tmp/test-symlink-2.sdat
dd bs=10 count=1 if=/dev/urandom of="$fname" 2>/dev/null
cp "$fname" ref.txt
ln -s "$fname" `basename $fname`

../../src/gs-transfer -s DkGDq3MU9BKfVg3DkobAHT
../../src/gs-transfer -s DkGDq3MU9BKfVg3DkobAHT -O >test-1.pipe

for x in tes*.dat tes*.pipe; do
	cmp "$x" "../${x}" >/dev/null
	if [ $? -ne 0 ]; then
		echo "ERROR: ${x}"
	fi
done

if [ -f /tmp/test-symlink-1.sdat ]; then
	echo "ERROR: Created file after following symlink"
fi

cmp /tmp/test-symlink-2.sdat ref.txt
if [ $? -ne 0 ]; then
	echo "ERROR: Overwrote /tmp/test-symlink-2.dat"
fi

