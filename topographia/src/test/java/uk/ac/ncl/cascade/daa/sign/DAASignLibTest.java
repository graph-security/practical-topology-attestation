package uk.ac.ncl.cascade.daa.sign;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.io.*;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DAASignLibTest {
    String libraryDAAPath = "/home/alpac/DEV/trousers-tss/src/tspi/daa/.libs";
    String libraryName = "topographia_daa_sign";

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void loadLib() {
        assertDoesNotThrow(() -> {
            String currentLibraryPath = System.getProperty("java.library.path");
            System.out.println("current library path: " + currentLibraryPath + "\n");
            System.setProperty("java.library.path", currentLibraryPath + File.pathSeparator + libraryDAAPath);
            currentLibraryPath = System.getProperty("java.library.path");
            System.out.println("library path: " + currentLibraryPath + "\n");
            System.loadLibrary(libraryName);
        });
    }

    @Test
    void executeDAA_Sign() {
        System.loadLibrary("topographia_daa_sign");
        String[] str = {""};
        int res = topographia_daa_sign.tp_daa_sign(str);
        assertTrue(res >= 0);
        String signResult = topographia_daa_sign.getSignResult();
        System.out.println("Signature verified : " + signResult);
        Assert.notNull(signResult, "daa sign did not return result");
    }

    @Test
    void readSignatureFile() throws IOException {
        String daaSignatureFilePath = "/home/alpac/DEV/topographia/signature.txt";
        BufferedReader reader = new BufferedReader(new FileReader(daaSignatureFilePath));

        int zetaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String zeta = reader.readLine().substring(0, zetaLength * 2);

        int capitalTLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalT = reader.readLine().substring(0, capitalTLength * 2);

        int challengeLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String challenge = reader.readLine().substring(0, challengeLength * 2);

        int nonceTpmLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String nonceTpm = reader.readLine().substring(0, nonceTpmLength * 2);

        int sVLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String sV = reader.readLine().substring(0, sVLength * 2);

        int sF0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String sF0 = reader.readLine().substring(0, sF0Length * 2);

        int sF1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String sF1 = reader.readLine().substring(0, sF1Length * 2);

        int sELength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String sE = reader.readLine().substring(0, sELength * 2);

        int signedPseudonymLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String signedPseudonym = reader.readLine().substring(0, signedPseudonymLength * 2);
//
        int flagLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String flag = reader.readLine().substring(0, flagLength );

        reader.close();

        // Print data
        Assert.notEmpty(zeta, "zeta is not part of the daa signature");
        System.out.println("Zeta: " + zeta);

        Assert.notEmpty(capitalT, "capitalT is not part of the daa signature");
        System.out.println("Capital T: " + capitalT);

        Assert.notEmpty(challenge, "challenge is not part of the daa signature");
        System.out.println("Challenge: " + challenge);

        Assert.notEmpty(nonceTpm, "nonce Tpm is not part of the daa signature");
        System.out.println("Nonce TPM: " + nonceTpm);

        Assert.notEmpty(sV, "sV is not part of the daa signature");
        System.out.println("sV: " + sV);

        Assert.notEmpty(sF0, "sF0 is not part of the daa signature");
        System.out.println("sF0: " + sF0);

        Assert.notEmpty(sF1, "sF1 is not part of the daa signature");
        System.out.println("sF1: " + sF1);

        Assert.notEmpty(sE, "sE is not part of the daa signature");
        System.out.println("sE: " + sE);

        Assert.notEmpty(signedPseudonym, "Signer Pseudonym is not part of the daa signature");
        System.out.println("Signed Pseudonym: " + signedPseudonym);
        System.out.println("Flag: " + flag);
    }
    @Test
    void readSignDataFile() throws IOException {
        String daaSignatureFilePath = "/home/alpac/DEV/topographia/sign-data.txt";
        BufferedReader reader = new BufferedReader(new FileReader(daaSignatureFilePath));

        int selectorLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String selector = reader.readLine().substring(0, selectorLength);

        int payloadFlagLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String payloadFlag = reader.readLine().substring(0, payloadFlagLength);

        int payloadLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String payload = reader.readLine().substring(0, payloadLength * 2);

        reader.close();

        Assert.notEmpty(selector, "selector is not part of the signed data file");
        System.out.println("selector: " + selector);

        Assert.notEmpty(payloadFlag, "payload flag is not part of the signed data file");
        System.out.println("Payload flag: " + payloadFlag);

        Assert.notEmpty(payload, "payload is not part of the signed data file");
        System.out.println("Payload: " + payload);

    }
}