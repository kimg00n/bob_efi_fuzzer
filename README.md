# BoB_EFI_Fuzzer

- EFI NVRAM Fuzzer by Best of the Best 11th.
- Inspired by efi_fuzz from Sentinel-One(https://github.com/Sentinel-One/efi_fuzz)

## How to use
    afl-fuzz -D -i afl_inputs/{varname} -o afl_outputs -U -- python3 ./main.py fuzz {target} -v {nvram} nvram {varname} @@