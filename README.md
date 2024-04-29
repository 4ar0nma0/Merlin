# Merlin
This is repository for <Merlin: multi-tier optimization of eBPF code for performance and compactness>

# Usage
## LLVM Passes (IR Refinement)
``` bash
git clone https://github.com/4ar0nma0/Merlin.git && cd Merlin
```
Before you do a cmake, change the llvm install dir and version in the cmakelist file in each directory.
After that, run cmake and make
``` bash
cmake .
make
```
You can find compiled .so library in ./lib directory.
To integrate the pass into compilation process, you need to use opt.
Alignment optimization:
``` bash
opt --load-pass-plugin ./lib/libAlignBPF.so -passes=alignbpf input.ll -o output.ll
```
Macro-op Fusion:
``` bash
opt --load-pass-plugin ./lib/libAtomicBPF.so -passes=atomicbpf input.ll -o output.ll
```
Together, but note put alignbpf before atomicbpf:
``` bash
opt --load-pass-plugin ./lib/libAtomicBPF.so --load-pass-plugin ./lib/libAtomicBPF.so -passes=alignbpf,atomicbpf input.ll -o output.ll
```

# License
MIT License

# Todo
Clean and upload bytecode level python script.
