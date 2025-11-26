        /*********************************************************************************
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2025 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how to perform Key Encapsulation operation using ML-KEM.
	- This sample required Luna Client 10.9.1 to execute.
	- Keypair and secret keys generated using this sample are ephemeral, i.e. a session objects.

*/

import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;
import javax.crypto.*;
import javax.crypto.KEM.*;
import javax.crypto.spec.IvParameterSpec;

public class KeyEncapsulationMechanism_MLKEM {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair mlkemKeyPair = null;
	private static SecretKey aesKey1 = null;
	private static SecretKey aesKey2 = null;
	private static IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
	private static final String PLAINTEXT = "Hello World, I've been waiting for the chance to see your face.";
	private static byte[] encrypted = null;
	private static byte[] decrypted = null;
	private static Encapsulated encapsulatedSecret = null;
	private static KEM mlKEM = null;
	private static final String PROVIDER = "LunaProvider";


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ KeyEncapsulationMechanism_MLKEM ]\n");
		System.out.println("Usage-");
		System.out.println("java KeyEncapsulationMechanism_MLKEM <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java KeyEncapsulationMechanism_MLKEM myPartition userpin\n");
	}


        // Add LunaProvider to security provider list.
        private static void addLunaProvider() {
                if(Security.getProvider(PROVIDER)==null) {
                        Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
                        System.out.println("LunaProvider added to java.security");
                } else {
                        System.out.println("LunaProvider found in java.security");
                }
        }


	// generates mlkem keypair
	private static void generateKeyPair() throws Exception {
		String mlkemParam = "ML-KEM-512"; // Other values : ML-KEM-786 and ML-KEM-1024.
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(mlkemParam, PROVIDER);
		mlkemKeyPair = keyPairGen.generateKeyPair();
		System.out.println("\nML-KEM keypair generated.");
	}


	// For Key Encapsulation : 
	// - Whoever has the ML-KEM Public key can encapsulate a secret and a ciphertext.
	// - They then share the ciphertext with the private key owner.
	private static void encapsulateKey() throws Exception {
		mlKEM = KEM.getInstance("ML-KEM", PROVIDER);
		Encapsulator encap = mlKEM.newEncapsulator(mlkemKeyPair.getPublic());
		encapsulatedSecret = encap.encapsulate(0, 32, "AES");
		aesKey1 = encapsulatedSecret.key();
		System.out.println("Secret key encapsulated.");
	}
		

	// The secret derived through encapsulation is then used for encrypting.
	private static void encryptData() throws Exception {
		Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
		encrypt.init(Cipher.ENCRYPT_MODE, aesKey1, ivSpec);
		encrypted = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
	}

	
	// For Key Decapsulation :
	// - The private key owner decapsulates the shared secret from the received ciphertext.
	private static void decapsulateKey() throws Exception {
		Decapsulator decap = mlKEM.newDecapsulator(mlkemKeyPair.getPrivate());
		aesKey2 = decap.decapsulate(encapsulatedSecret.encapsulation(), 0, 32, "AES");
		System.out.println("Secret key decapsulated.");
	}


	// Decapsulated secret can then be used for decrypting an encrypted data.
	private static void decryptData() throws Exception {
		Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, aesKey2, ivSpec);
		decrypted = decrypt.doFinal(encrypted);
		System.out.println("Encrypted data decrypted.");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKeyPair();
				encapsulateKey();
				encryptData();
				decapsulateKey();
				decryptData();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
