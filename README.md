# BoB_EFI_Fuzzer

- EFI NVRAM Fuzzer by Best of the Best 11th.
- Improved qiling and AFL++ version NVRAM fuzzing in [efi_fuzz](https://github.com/Sentinel-One/efi_fuzz) from Sentinel-One
- It is compatible with the latest version of [qiling](https://github.com/qilingframework/qiling) & [AFL++](https://github.com/AFLplusplus/AFLplusplus)(qiling=1.4.4, AFL++=4.03c)

## Install AFL++ & unicornafl
  - install AFL++
  ```
  git clone https://github.com/AFLplusplus/AFLplusplus
  cd AFLplusplus
  make distrib
  sudo make install
  ```

  - install unicornafl
  ```
  git submodule update --init --recursive
  cd bindings/python/
  python3 -m pip install -e .
  ```

  - You have to change unicornafl.py
  ```
  err = _uc2afl.uc_afl_fuzz(uc._uch, input_file.encode("utf-8"), cb1, ctypes.cast(
      exits_array, ctypes.c_void_p), exits_len, cb2, always_validate, persistent_iters, ctypes.cast(idx, ctypes.c_void_p))

  if err != UC_AFL_RET_OK:
      del _data_dict[idx]
      raise UcAflError(err)
  ```
  to
  ```
  err = _uc2afl.uc_afl_fuzz(uc._uch, input_file.encode("utf-8"), cb1, ctypes.cast(
      exits_array, ctypes.c_void_p), exits_len, cb2, always_validate, persistent_iters, ctypes.cast(idx, ctypes.c_void_p))

  if err == UC_AFL_RET_NO_AFL:
      return False

  elif err != UC_AFL_RET_OK:
      del _data_dict[idx]
      raise UcAflError(err)
  ```

## How to use
    afl-fuzz -D -i afl_inputs/{varname} -o afl_outputs -U -- python3 ./main.py fuzz {target} -v {nvram} nvram {varname} @@