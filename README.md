# [ LUNA SAMPLES ]

This repository contains various sample codes designed to work across all variants of [Luna General Purpose HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms), unless otherwise noted in the comments. These variants includes
- [Luna Network HSM 7](https://cpl.thalesgroup.com/sites/default/files/content/product_briefs/luna-sa-network-attached-hsm-pb.pdf).
- [Luna PCIe HSM 7](https://cpl.thalesgroup.com/sites/default/files/content/product_briefs/field_document/2024-04/Thales-Luna-PCIe-HSM-pb.pdf).
- [Luna USB HSM (Luna U700)](https://cpl.thalesgroup.com/sites/default/files/content/product_briefs/field_document/2022-09/luna-usb-hsm-pb.pdf).
- [Luna Cloud HSM a.k.a Data Protection on Demand(DPoD)](https://cpl.thalesgroup.com/sites/default/files/content/solution_briefs/data-protection-on-demand-services-sb.pdf).
- Luna G5 (EOL - Sep-2025).
- Previous Generation of Luna HSM.

<br><br>

Features -

+ **Universal Compatibility**: The sample codes are compatible with all Luna HSM variants unless explicitly mentioned.

+ **Well-Documented**: Each sample code is thoroughly commented to explain its purpose and functionality.

+ **Tested**:  All samples have been tested and should work under the right conditions. Some samples may require specific policies to be enabled.

+ **Well-Formatted**: Samples are well-formatted, easy to read, properly indented, and free from unnecessary comments and other extraneous material.

+ **Topics Covered**: The samples in this repository would cover the following topics:
	- PKCS#11.
	- Luna JSP.
	- Luna RestAPI
+ **Languages Covered**: Samples available for C, Java.

<br><br>

## Content

| Directory Name  | Description   |
| --- | --- |
| C_Samples | Pkcs11 samples written in C language. |
| LunaJSP_Samples | Java samples that uses LunaProvider (Luna JSP). |
| RestAPI-Python_Samples | Python3 based Luna REST-API samples for Luna Network HSM. |
| Python-PKCS11_Samples | Python3 based samples to demonstrate how to use python-pkcs11. |
| Luna-FM_Samples | additional samples codes to demonstrate and test FM capability of Luna HSM. |

<br><br>

## Contributing

If you are interested in contributing to the "LunaHSM_Sample_Codes", start by reading the [Contributing guide](/CONTRIBUTING.md).


## License

This software is provided under a [permissive license](LICENSE).
