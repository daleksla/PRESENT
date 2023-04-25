rm -r build || true
mkdir build
cd build
cmake ..
cmake --build .
cd ..
