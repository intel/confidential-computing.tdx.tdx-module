<!--******************************************************************************
* Copyright (C) 2023 Intel Corporation                                        
*                                                                             
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"),       
* to deal in the Software without restriction, including without limitation   
* the rights to use, copy, modify, merge, publish, distribute, sublicense,    
* and/or sell copies of the Software, and to permit persons to whom           
* the Software is furnished to do so, subject to the following conditions:    
*                                                                             
* The above copyright notice and this permission notice shall be included     
* in all copies or substantial portions of the Software.                      
*                                                                             
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS     
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL    
* THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES           
* OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,    
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE          
* OR OTHER DEALINGS IN THE SOFTWARE.                                          
*                                                                             
* SPDX-License-Identifier: MIT
******************************************************************************/-->

As stated in the [README](README.md), the objectives of the TDX module's open-source initiative are to review its source code and to provide users with the capability to verify the exact source code that corresponds to Intel released signed TDX Module binary. To create a binary that is identical to the official release binary, it is essential to adhere to the provided [build instructions](BUILD.md). Signed binaries are available as release assets for every release and could be found [here](https://github.com/intel/confidential-computing.tdx.tdx-module/releases). 

# Guidelines for Contributions: 
- Please note that this repository does not serve as a platform for TDX Module development. Consequently, pull requests submitted to this repository will not be reviewed or considered for integration. 
- Contributions must adhere to stringent standards to ensure they align with the TDX module's security goals, compatibility with upcoming SoCs, and customer needs for TDX technology. Consider these factors carefully when submitting an issue or proposing a solution. 

# How Can You Contribute? 
Your contributions are encouraged to enhance the TDX Module's quality and its build recipe. 
To make a contribution, please open an issue with the following information: 
- The specific TDX Module version(s) where the issue was identified. 
- A clear description of the issue. 
- Steps or methods to reproduce the issue. 
- If available, a proposed solution to address the issue. 

The TDX development team will review all issues submitted. Accepted suggestions may be incorporated into future releases, potentially with modifications. 