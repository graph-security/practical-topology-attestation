package uk.ac.ncl.cascade.daa.join;

import uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class DAACredential {
    private String capitalA;
    private String exponent;
    private String vBar0;
    private String vBar1;
    private String modulus;
    private String capitalS;
    private String capitalZ;
    private String capitalR0;
    private String capitalR1;
    private String gamma;
    private String capitalGamma;
    private String rho;
    private String capitalRReceiver0;
    private String capitalRReceiver1;
    private String capitalRIssuer0;
    private String capitalRIssuer1;
    private String capitalRIssuer2;
    private String baseName;
    private String tpmSpecific;
    private String capitalNi;

    public DAACredential() {

    }

    public String getCapitalA() {
        return capitalA;
    }

    public String getExponent() {
        return exponent;
    }

    public String getvBar0() {
        return vBar0;
    }

    public String getvBar1() {
        return vBar1;
    }

    public String getModulus() {
        return modulus;
    }

    public String getCapitalS() {
        return capitalS;
    }

    public String getCapitalZ() {
        return capitalZ;
    }

    public String getCapitalR0() {
        return capitalR0;
    }

    public String getCapitalR1() {
        return capitalR1;
    }

    public String getGamma() {
        return gamma;
    }

    public String getCapitalGamma() {
        return capitalGamma;
    }

    public String getRho() {
        return rho;
    }

    public String getCapitalRReceiver0() {
        return capitalRReceiver0;
    }

    public String getCapitalRReceiver1() {
        return capitalRReceiver1;
    }

    public String getCapitalRIssuer0() {
        return capitalRIssuer0;
    }

    public String getCapitalRIssuer1() {
        return capitalRIssuer1;
    }

    public String getCapitalRIssuer2() {
        return capitalRIssuer2;
    }

    public String getBaseName() {
        return baseName;
    }

    public String getTpmSpecific() {
        return tpmSpecific;
    }

    public String getCapitalNi() {
        return capitalNi;
    }

    public void readCredentialFile() throws IOException {

        BufferedReader reader = new BufferedReader(new FileReader(TopographiaDefaultOptionValues.DEF_DAA_CREDENTIAL));
        int capitalALength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalA = reader.readLine().substring(0, capitalALength * 2);

        int exponentLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        exponent = reader.readLine().substring(0, exponentLength * 2);

        int vBar0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        vBar0 = reader.readLine().substring(0, vBar0Length * 2);

        int vBar1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        vBar1 = reader.readLine().substring(0, vBar1Length * 2);

        int modulusLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        modulus = reader.readLine().substring(0, modulusLength * 2);

        int capitalSLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalS = reader.readLine().substring(0, capitalSLength * 2);

        int capitalZLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalZ = reader.readLine().substring(0, capitalZLength * 2);

        int capitalR0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalR0 = reader.readLine().substring(0, capitalR0Length * 2);

        int capitalR1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalR1 = reader.readLine().substring(0, capitalR1Length * 2);

        int gammaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        gamma = reader.readLine().substring(0, gammaLength * 2);

        int capitalGammaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalGamma = reader.readLine().substring(0, capitalGammaLength * 2);

        int rhoLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        rho = reader.readLine().substring(0, rhoLength * 2);

        int capitalRReceiverLength = Integer.parseInt(reader.readLine().split(" ")[0]);

        int capitalRReceiver0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalRReceiver0 = reader.readLine().substring(0, capitalRReceiver0Length * 2);

        int capitalRReceiver1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalRReceiver1 = reader.readLine().substring(0, capitalRReceiver1Length);

        int capitalRIssuerLength = Integer.parseInt(reader.readLine().split(" ")[0]);

        int capitalRIssuer0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalRIssuer0 = reader.readLine().substring(0, capitalRIssuer0Length * 2);

        int capitalRIssuer1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalRIssuer1 = reader.readLine().substring(0, capitalRIssuer1Length * 2);

        int capitalRIssuer2Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalRIssuer2 = reader.readLine().substring(0, capitalRIssuer2Length * 2);

        int baseNameLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        baseName = reader.readLine().substring(0, baseNameLength);

        int tpmSpecificLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        tpmSpecific = reader.readLine().substring(0, tpmSpecificLength * 2);

        int daaCounter = Integer.parseInt(reader.readLine().split(" ")[0]);

        int capitalNiLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalNi = reader.readLine().substring(0, capitalNiLength * 2);

        reader.close();

    }
}
