rm -rf bin/
mkdir bin
cp raw/test.* bin
cd bin
case $1 in
    "release") cmake -DCMAKE_BUILD_TYPE=Release ..;;
    "debug") cmake -DCMAKE_BUILD_TYPE=Debug ..;;
    *) cmake -DCMAKE_BUILD_TYPE=Release ..;;
esac
make
