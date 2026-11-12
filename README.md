<!---
Copyright (C) 2023-2026 Intel Corporation
SPDX-License-Identifier: MIT
-->
# Intel TDX Module - Source Code Repository

Welcome to the landing page of the Intel TDX Module repository containing source code.
On this landing page, we provide pointers to the main project branches.
Additionally, we provide a list of Intel TDX Module releases and corresponding hashes.

In most cases, the source code for these Intel TDX Module versions is public.
With this open-source initiative, we provide users with the capability to reproduce the official binaries, which are signed and provided by Intel.
To create a binary that is identical to the official release binary, it is essential to adhere to the build instructions provided in the specific project release, which can be found on the [releases page](https://github.com/intel/confidential-computing.tdx.tdx-module/releases).
The same page also contains signed binaries.

For more details on Intel TDX, refer to the corresponding [documentation overview page](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html).

## Project Branches

This repository contains the following main branches:

- **[`tdx_1.5` for Intel TDX Module versions 1.5.x](https://github.com/intel/confidential-computing.tdx.tdx-module/tree/tdx_1.5)**
- **[`tdx_2.0` for Intel TDX Module versions 2.0.x](https://github.com/intel/confidential-computing.tdx.tdx-module/tree/tdx_2.0)**

## Intel TDX Module Releases and Hashes

In the following, we list all Intel TDX Module releases covered by this repository.
For all versions with released source code, we provide a link to the corresponding release.

In all cases, we provide MRSEAM (Measurement Register for SEAM), a SHA-384 hash uniquely identifying a particular Intel TDX Module version.
The hash is computed during the module loading process - it reflects the exact contents of the module code and initial data.

| Version | MRSEAM                                                                                                     |
|---------|-----------------------------------------------------------------------------------------------------------|
| [1.5.01](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.01)  | 0x9790D89A10210EC6968A773CEE2CA05B5AA97309F36727A968527BE4606FC19E6F73ACCE350946C9D46A9BF7A63F8430 |
| [1.5.05](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.05)  | 0x1CC6A17AB799E9A693FAC7536BE61C12EE1E0FABADA82D0C999E08CCEE2AA86DE77B0870F558C570E7FFE55D6D47FA04 |
| [1.5.06](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.06)  | 0x5B38E33A6487958B72C3C12A938EAA5E3FD4510C51AEEAB58C7D5ECEE41D7C436489D6C8E4F92F160B7CAD34207B00C1 |
| [1.5.08](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.08)  | 0x49B66FAA451D19EBBDBE89371B8DAF2B65AA3984EC90110343E9E2EEC116AF08850FA20E3B1AA9A874D77A65380EE7E6 |
| [1.5.09](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.09)  | 0xBFB360AC8E6233A1BCA1433CAF7382D95C165B4A77FB00BF1435E5A08F300CDFEAD5EE68461AFD9B6C728DCE7534602D |
| [1.5.13](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.13)  | 0x27B67E0B20508F0ACFB8A99DF4283A7C86AE569D85D556A91D4EB20E56B5D42D5E65B31A3A6996E8E461F104F32FDEEC |
| [1.5.16](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.16)  | 0x7BF063280E94FB051F5DD7B1FC59CE9AAC42BB961DF8D44B709C9B0FF87A7B4DF648657BA6D1189589FEAB1D5A3C9A9D |
| [1.5.20](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.20)  | 0xD0D80C085166BA78CCC69AF268E5753CF0F3394523CB4FF7C50B08D9265C82489C099C377BE6A400E4D2B57DA924012C |
| [1.5.24](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.24)  | 0x489E585F1C54BC5A02066C8C6EC21619FF0334EC6F21E07E2A35202C59183789C8057E7D97DD591BB08314B185819E72 |
| [1.5.25](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.25)  | 0xFCA4FF221293807E3D247416299CA39A236872DF4EB414567CA96072D3FDE7DEAD740F807EEFE2F7D938499C03CC8ABA |
| [1.5.28](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.28)  | 0x346BC77A1846CAC214DD2E8EDEB9EE4349449D6C3F9FF2C52149A634C27B7FD1BD314C2EF6B973EEEBD55742952531A1 |
| [1.5.34](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.34)  | 0xAB62561A173ACBD18EE50FF37750DB44184C6CF5E886DF74247CC575E163B04C34B9E18374757C235AFFA614D4127F6B |
| [1.5.36](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.36)  | 0x06B9E658F3C3D929CEACF71A49A49DEFB992927DD31F104825D0AEE04C7ABF5ABE688E00E949B48AAFFD6FC6BEF9AC84 |
| [2.0.02](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.02)  | 0x685F891EA5C20E8FA27B151BF34BF3B50FBAF7143CC53662727CBDB167C0AD8385F1F6F3571539A91E104A1C96D75E04 |
| [2.0.04](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.04)  | 0x64CAE497E0C6221176FE8D3BC9D0CF25B4C97BB24CC16499F77102451F15BB24249F1AA3E5D3BF8897BE74AD6C84E648 |
| [2.0.08](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.08)  | 0x476A2997C62BCCC78370913D0A80B956E3721B24272BC66C4D6307CED4BE2865C40E26AFAC75F12DF3425B03EB59EA7C |
| [2.0.12](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.12)  | 0x87BDF50356B95E264A5D0807016B9B8AB7568D0857D27EDDBE847F98184A786E0F3EECF2FABD3B6D23F71F2AE50300F4 |
| [2.0.14](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.14)  | 0xAEF4ED3E686FE6CF44C9A8D1CC63105443B558AC4F40C282ABF78271E9A4586C50408C8584C7B43FD21EDB736700BA5F |
| [2.0.16](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.16)  | 0xF40772D82608DA5443887DD7247BE3E0092927E62409A9BB8DA98EAED9017704BE075466A13D3CA30501000D69407495 |
| [2.0.18](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.18)  | 0x2D2DE102461684F14C8D0984A09D895E3E9E15944CE020A03B977E1F114D5E1ED32EF666A47FD19A5851B3800EDA3AFA |
| [2.0.20](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.20)  | 0x57A1A66F3704887A9FBF64AAE610421BC10D428C5E0EB10ACD0E3CAB8363CD8A1A92E276F3238A5C6C7A9C95A2C0FC82 |


## Additional Resources

- [CONTRIBUTING.md](CONTRIBUTING.md) - Guidelines on how to contribute to this repository
- [LICENSE](LICENSE) - License information for this project
