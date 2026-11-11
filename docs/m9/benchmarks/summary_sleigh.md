| Binary | Condition | Cold s, median (range, n) | Warm s | Cached s | Cold freeze-free | Warm freeze-free | Facts digests |
|---|---|---|---|---|---|---|---|
| aire_test_binary | i-before | 14.84 (11.50–20.52, n=5) | 4.85 (4.71–8.18, n=5) | 0.0061 (0.0048–0.0180, n=5) | 14.67 (14.24–15.11, n=2) | 5.73 (4.82–6.63, n=2) | 1 |
| aire_test_binary | i-after | 19.72 (14.90–240.66, n=5) | 6.11 (4.75–9.11, n=5) | 0.0079 (0.0043–0.0127, n=5) | 22.16 (22.16–22.16, n=1) | 6.93 (4.75–9.11, n=2) | 1 |
| TLS.exe | i-before | 34.01 (21.65–128.68, n=5) | 13.23 (9.54–44.24, n=5) | 0.0268 (0.0168–0.0323, n=5) | 21.65 (21.65–21.65, n=1) | — | 1 |
| TLS.exe | i-after | 26.45 (21.04–96.24, n=5) | 9.81 (7.72–84.04, n=5) | 0.0206 (0.0168–0.0302, n=5) | 24.57 (21.04–28.10, n=2) | 7.72 (7.72–7.72, n=1) | 1 |
| FunctionOverloading.exe | i-before | 29.22 (21.51–83.00, n=5) | 15.18 (10.94–408.30, n=5) | 0.0289 (0.0184–0.0392, n=5) | 23.45 (21.51–25.39, n=2) | 11.11 (10.94–11.29, n=2) | 2 |
| FunctionOverloading.exe | i-after | 33.21 (25.73–227.19, n=5) | 11.06 (10.19–297.13, n=5) | 0.0239 (0.0184–0.0926, n=5) | 25.73 (25.73–25.73, n=1) | 10.56 (10.19–10.93, n=2) | 1 |
| sleigh.exe | i-before | 220.13 (205.42–594.55, n=5) | — | 0.6969 (0.5061–1.2867, n=5) | — | — | 2 |
| sleigh.exe | i-after | 227.84 (138.33–247.92, n=5) | — | 0.5452 (0.5009–0.6284, n=5) | — | — | 1 |

| Binary | Stage (cold median s) | i-before | i-after |
|---|---|---|---|
| aire_test_binary | runtime_startup | 3.33 | 4.85 |
| aire_test_binary | import_open | 2.89 | 3.20 |
| aire_test_binary | auto_analysis | 6.82 | 9.48 |
| aire_test_binary | decompiler_setup | 0.36 | 0.43 |
| aire_test_binary | decompilation | 0.36 | 0.09 |
| aire_test_binary | assembly | 0.05 | 0.10 |
| aire_test_binary | basic_blocks | 0.03 | 0.11 |
| aire_test_binary | xrefs | 0.06 | 0.07 |
| aire_test_binary | call_graph | 0.01 | 0.01 |
| aire_test_binary | database_save | 0.03 | 0.03 |
| TLS.exe | runtime_startup | 3.96 | 4.88 |
| TLS.exe | import_open | 2.86 | 4.01 |
| TLS.exe | auto_analysis | 15.89 | 13.08 |
| TLS.exe | decompiler_setup | 0.30 | 0.49 |
| TLS.exe | decompilation | 3.07 | 1.11 |
| TLS.exe | assembly | 0.12 | 0.36 |
| TLS.exe | basic_blocks | 0.10 | 0.30 |
| TLS.exe | xrefs | 0.17 | 0.21 |
| TLS.exe | call_graph | 0.05 | 0.06 |
| TLS.exe | database_save | 0.06 | 0.07 |
| FunctionOverloading.exe | runtime_startup | 3.95 | 4.81 |
| FunctionOverloading.exe | import_open | 2.54 | 5.22 |
| FunctionOverloading.exe | auto_analysis | 15.12 | 14.13 |
| FunctionOverloading.exe | decompiler_setup | 0.23 | 0.63 |
| FunctionOverloading.exe | decompilation | 4.41 | 1.35 |
| FunctionOverloading.exe | assembly | 0.12 | 0.65 |
| FunctionOverloading.exe | basic_blocks | 0.09 | 0.42 |
| FunctionOverloading.exe | xrefs | 0.14 | 0.22 |
| FunctionOverloading.exe | call_graph | 0.04 | 0.05 |
| FunctionOverloading.exe | database_save | 0.07 | 0.07 |
| sleigh.exe | runtime_startup | 3.90 | 3.95 |
| sleigh.exe | import_open | 4.30 | 4.22 |
| sleigh.exe | auto_analysis | 124.61 | 91.63 |
| sleigh.exe | decompiler_setup | 0.24 | 0.62 |
| sleigh.exe | decompilation | 73.55 | 20.82 |
| sleigh.exe | assembly | 2.69 | 8.54 |
| sleigh.exe | basic_blocks | 1.21 | 3.56 |
| sleigh.exe | xrefs | 4.84 | 4.22 |
| sleigh.exe | call_graph | 1.38 | 1.16 |
| sleigh.exe | database_save | 1.69 | 1.52 |

- aire_test_binary: facts identical across i-before, i-after: **True**
- TLS.exe: facts identical across i-before, i-after: **True**
- FunctionOverloading.exe: facts identical across i-before, i-after: **False**
- sleigh.exe: facts identical across i-before, i-after: **False**
