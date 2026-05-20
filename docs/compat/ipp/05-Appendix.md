# Appendix

## Compiling and Installing IPPCP

For the official guide on how to compile and install IPPCP [click here](https://github.com/intel/cryptography-primitives/blob/develop/BUILD.md)

```bash
git clone https://github.com/intel/cryptography-primitives.git -b ippcp_2021.12.1
cd cryptography-primitives
mkdir build
cd build
cmake ../ -DCMAKE_INSTALL_PREFIX=/usr/local -DARCH=intel64
make -j$(nproc --all) # Low memory, override the -j parameter.
sudo make install
```

**For setting up environment.** 

This is normally not required, if you face errors please add these to your bashrc/zshrc/somerc

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export LIBRARY_PATH=/usr/local/lib:$LIBRARY_PATH
export PATH=/usr/local/bin:$PATH
export C_INCLUDE_PATH=/usr/local/include:$C_INCLUDE_PATH
export CPLUS_INCLUDE_PATH=/usr/local/include:$CPLUS_INCLUDE_PATH
```
