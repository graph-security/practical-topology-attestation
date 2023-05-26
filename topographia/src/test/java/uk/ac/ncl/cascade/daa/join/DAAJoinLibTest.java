package uk.ac.ncl.cascade.daa.join;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DAAJoinLibTest {
    String libraryDAAPath = "/home/alpac/DEV/trousers-tss/src/tspi/daa/.libs";
    String libraryName = "topographia_daa_join";
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
    void executeDAA_Join() {
        System.loadLibrary("topographia_daa_join");
        String[] str = {""};
        int res = topographia_daa_join.tp_daa_join(str);
        assertTrue(res>=0);
        String ng = topographia_daa_join.getNG();
        assertNotNull(ng);
        BigInteger bi = new BigInteger(ng, 16);
        assertNotNull(bi);
    }

    @Test
    void readCredentialFile() throws IOException {
        String daaSignatureFilePath = "/home/alpac/DEV/topographia/credential.txt";
        BufferedReader reader = new BufferedReader(new FileReader(daaSignatureFilePath));

        int capitalALength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalA = reader.readLine().substring(0, capitalALength * 2);

        int exponentLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String exponent = reader.readLine().substring(0, exponentLength * 2);

        int vBar0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String vBar0 = reader.readLine().substring(0,vBar0Length * 2);

        int vBar1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String vBar1 = reader.readLine().substring(0,vBar1Length * 2);
// pk internal
        int modulusLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String modulus = reader.readLine().substring(0, modulusLength * 2);

        int capitalSLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalS = reader.readLine().substring(0, capitalSLength * 2);

        int capitalZLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalZ = reader.readLine().substring(0, capitalZLength* 2);

        int capitalR0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalR0 = reader.readLine().substring(0, capitalR0Length * 2);

        int capitalR1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalR1 = reader.readLine().substring(0, capitalR1Length * 2);

        int gammaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String gamma = reader.readLine().substring(0, gammaLength * 2);

        int capitalGammaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalGamma = reader.readLine().substring(0, capitalGammaLength * 2);

        int rhoLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String rho = reader.readLine().substring(0, rhoLength * 2);


        int capitalRReceiverLength = Integer.parseInt(reader.readLine().split(" ")[0]);

        int capitalRReceiver0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalRReceiver0 = reader.readLine().substring(0, capitalRReceiver0Length * 2);
        
        int capitalRReceiver1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalRReceiver1 = reader.readLine().substring(0, capitalRReceiver1Length);

        int capitalRIssuerLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        
        int capitalRIssuer0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalRIssuer0 = reader.readLine().substring(0, capitalRIssuer0Length * 2);

        int capitalRIssuer1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalRIssuer1 = reader.readLine().substring(0, capitalRIssuer1Length * 2);

        int capitalRIssuer2Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalRIssuer2 = reader.readLine().substring(0, capitalRIssuer2Length * 2);

        int baseNameLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String baseName = reader.readLine().substring(0, baseNameLength );

        int tpmSpecificLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String tpmSpecific = reader.readLine().substring(0, tpmSpecificLength * 2);

        int daaCounter = Integer.parseInt(reader.readLine().split(" ")[0]);

        int capitalNiLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        String capitalNi = reader.readLine().substring(0, capitalNiLength * 2 );

        reader.close();

        // Print data
        Assert.notEmpty(capitalA, "capitalA is not part of the daa credential");
        System.out.println("capitalA: " + capitalA);

        Assert.notEmpty(exponent, "exponent is not part of the daa credential");
        System.out.println("exponent: " + exponent);

        Assert.notEmpty(vBar0, "vBar0 is not part of the daa credential");
        System.out.println("vBar0: " + vBar0);

        Assert.notEmpty(vBar1, "vBar1 is not part of the daa credential");
        System.out.println("vBar1: " + vBar1);
        
        Assert.notEmpty(modulus, "modulus is not part of the daa credential");
        System.out.println("modulus: " + modulus);

        Assert.notEmpty(capitalS, "capitalS is not part of the daa credential");
        System.out.println("capitalS : " + capitalS);

        Assert.notEmpty(capitalZ, "capitalZ is not part of the daa credential");
        System.out.println("capitalZ : " + capitalZ);
        
        Assert.notEmpty(capitalR0, "capitalR0 is not part of the daa credential");
        System.out.println("capitalR0 : " + capitalR0);
        
        Assert.notEmpty(capitalR1, "capitalR1 is not part of the daa credential");
        System.out.println("capitalR1 : " + capitalR1);
        
        Assert.notEmpty(gamma, "gamma is not part of the daa credential");
        System.out.println("gamma : " + gamma);

        Assert.notEmpty(capitalGamma, "capitalGamma is not part of the daa credential");
        System.out.println("capitalGamma : " + capitalGamma);

        Assert.notEmpty(capitalRReceiver0, "capitalRReceiver0 is not part of the daa credential");
        System.out.println("capitalRReceiver0: " + capitalRReceiver0);
        
        Assert.notEmpty(capitalRReceiver1, "capitalRReceiver1 is not part of the daa credential");
        System.out.println("capitalRReceiver1: " + capitalRReceiver1);

        Assert.notEmpty(capitalRIssuer0, "capitalRIssuer0 is not part of the daa credential");
        System.out.println("capitalRIssuer0: " + capitalRIssuer0);
        
        Assert.notEmpty(capitalRIssuer1, "capitalRIssuer1 is not part of the daa credential");
        System.out.println("capitalRIssuer1: " + capitalRIssuer1);
        
        Assert.notEmpty(capitalRIssuer2, "capitalRIssuer2 is not part of the daa credential");
        System.out.println("capitalRIssuer2: " + capitalRIssuer2);
        
        Assert.notEmpty(baseName, "baseName is not part of the daa credential");
        System.out.println("baseName: " + baseName);

        Assert.notEmpty(tpmSpecific, "tpmSpecific is not part of the daa credential");
        System.out.println("tpmSpecific: " + tpmSpecific);
        
        Assert.notEmpty(capitalNi, "capitalNi  is not part of the daa credential");
        System.out.println("capitalNi: " + capitalNi + "\n");
    }
}
