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

- [Build Environment](#build-environment)
- [Docker Container Build Instructions](#docker-container-build-instructions)
- [How to Build](#how-to-build)
- [Environment Dependencies](#environment-dependencies)
- [Make Targets](#make-targets)

# Build Environment

This repo contains a docker file for your convenience.  
SW prerequisites could be found in the [Dockerfile](Dockerfile) (prerequisites could be installed also manually).  
Please note that the TDX module isn't part of the docker image and the user must build it according to the [instructions below](#how-to-build).

## Docker Container Build Instructions:

1. Clone/download the desired TDX module version ([Releases](https://github.com/intel/confidential-computing.tdx.tdx-module/releases)).  
2. Build the Docker image from the [Dockerfile](Dockerfile) (located inside the relevant repo) at the root:  
```docker build . -t tdx-module-docker```

3. Run the Docker container from the local created docker image:  
```docker run -ti --rm --net=host -v "$PWD":$HOME/tdx-module -w $HOME/tdx-module tdx-module-docker bash```  
NOTE: In order to run on Windows, replace the mount line with: -v "%CD%":$HOME/tdx-module


# How to Build
## Environment dependencies

- Binary padding script

- Compiled on Linux* OS

- [ICP 1.0.1](https://github.com/intel/cryptography-primitives/releases/tag/v1.0.1):

ICP will be automatically built by project's makefile.

- ICP sources need to be placed under ./libs/ipp/cryptography-primitives-1.0.1 folder.

- Tools that are required to build ICP crypto lib described in the following [link](https://github.com/intel/cryptography-primitives/blob/v1.0.1/BUILD.md)

## Make targets
Binary's generation includes the date it was compiled at, build number and module's update version.  

Build date, build number and update version could be extracted from the production binary, please use TDH.SYS.RD SEAMCALL (leaf #34) with MD_SYS_TDX_MODULE_VERSION_CLASS_CODE(8) as a class_code and MD_SYS_BUILD_DATE_FIELD_CODE(1)/MD_SYS_BUILD_NUM_FIELD_CODE(2)/MD_SYS_UPDATE_VERSION_FIELD_CODE(5) as field codes. The date format should be YYYYMMDD.  

Current TDX version was built with: TDX_MODULE_BUILD_DATE=20260514 TDX_MODULE_BUILD_NUM=1073 TDX_MODULE_UPDATE_VER=36

1) In order to reproduce the exact binary, it is required to specify the original date, build number and update version:

	```bash
	make RELEASE=1 TDX_MODULE_BUILD_DATE=20260514 TDX_MODULE_BUILD_NUM=1073 TDX_MODULE_UPDATE_VER=36
	```

	In case binary reproduction is not required, "make RELEASE=1" will suffice.

2) Clean everything:

	```bash
	make clean
	```

3) Clean everything including the ICP:

	```bash
	make cleanall
	```


## Expected module hash (MRSEAM)
0x28254B2AA0CB27A98B3A02554556870CE8FA922C4886DBBFB98B0F638ECD1ED0CA5D87D5F43826980D363004808D17B4
