        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how to load KeyStore of type Luna.
	- This is another way to login to a partition/slot.
	- This sample uses slotlabel to login.
	- There is no logout function in Java KeyStore so LunaProvider is programmed to logout before an application close(finalize).
*/


import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class LoadLunaKeyStoreUsing_SlotLabel {

	private static String slotPassword = null;
	private static String slotLabel = null;

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ LoadLunaKeyStoreUsing_SlotLabel ]\n");
		System.out.println("Usage-");
		System.out.println("java LoadLunaKeyStoreUsing_SlotLabel <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java LoadLunaKeyStoreUsing_SlotLabel myPartition userpin\n");
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


	// loads Luna KeyStore (calls C_Login).
	private static void loadKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		KeyStore lunaKeyStore = KeyStore.getInstance("Luna");
		lunaKeyStore.load(new ByteArrayInputStream(("tokenlabel:"+slotLabel).getBytes()), slotPassword.toCharArray());
		System.out.println("Luna KeyStore loaded successfully.");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];

			addLunaProvider();
			loadKeyStore();
		} catch(ArrayIndexOutOfBoundsException aioe) {
			System.out.println("\nERROR: Please pass slot-label and crypto-officer password as an argument.\n");
			printUsage();
			System.exit(1);
		} catch(Exception exception) {
			System.out.println("\nERROR: " + exception.getMessage());
		}
	}
}
