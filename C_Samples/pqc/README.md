
### PQC SAMPLES FOR LUNA HSM.

<br>

>[!NOTE]
> These samples require a Luna HSM that supports the specified mechanism.
> HSS samples require the Universal client 10.8.0 or later to compile.
> ML-DSA and ML-KEM samples require the Universal client 10.9.0 or later to compile.

<br>

| FILE_NAME | DESCRIPTION | FIRMWARE REQUIRED |
| --- | --- | --- |
| CKM_HSS_KEY_PAIR_GEN_demo.c | demonstrates how to generate an HSS key pair. | v7.8.9 or newer |
| CKM_HSS_sign_demo.c | demonstrates how to sign data from a file using HSS. | v7.8.9 or newer |
| CKM_HSS_verify_demo.c | demonstrates how to verify a digital signature using HSS. | v7.8.9  or newer |
| CKM_ML_DSA_KEY_PAIR_GEN_demo.c | demonstrates how to generate an ML-DSA keypair. | v7.9.0 or newer |
| CKM_ML_KEM_KEY_PAIR_GEN_demo.c | demonstrates how to generate an ML-KEM keypair. | v7.9.0 or newer |
| CKM_ML_DSA_Sign_Verify_demo.c | demonstrates how to generate and verify pure ML-DSA signature, using an ML-DSA keypair. | v7.9.0 or newer |
| CKM_EXTMU_ML_DSA_Sign_Verify_demo.c | demonstrates how to generate and verify ML-DSA signature using externally computer mu value. | v7.9.0 or newer |
| CKM_HASH_ML_DSA_Sign_Verify_demo.c | demonstrates how to generate a signature from a pre-computed hash using an ML-DSA keypair. | v7.9.0 or newer |
| CKM_HASH_ML_DSA_SHA3_512_Sign_Verify_demo.c | demonstrates how to generated a hashed ML-DSA signature. | v7.9.0 or newer |
| CKM_ML_KEM_Encapsulate_Decapsulate_demo.c | demonstrates how to encapsulate and decapsulate an AES-256 key using ML-KEM. | v7.9.0 or newer. |
| Wrap_PQC_PrivateKey_demo.c | demonstrates how to wrap private key of type ML-DSA and ML-KEM from a Luna partition. | v7.9.1 or newer. |
| Unwrap_PQC_PrivateKey_demo.c | demonstrates how to unwrap a wrapped private key of type ML-DSA and ML-KEM into a Luna partition. | v7.9.1 or newer. |
<br>

For help with compiling and executing the code, please refer to the HOW_TO guide provided here : [HOW_TO](/C_Samples/HOW_TO.md).
