package uk.ac.ncl.cascade.daa.sign;

import uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class DAASignature {

    private String zeta;
    private String capitalT;
    private String challenge;
    private String nonceTpm;
    private String sV;
    private String sF0;
    private String sF1;
    private String sE;
    private String signedPseudonym;
    private String flag;

    public DAASignature(){

    }

    public String getZeta() {
        return zeta;
    }

    public String getCapitalT() {
        return capitalT;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getNonceTpm() {
        return nonceTpm;
    }

    public String getsV() {
        return sV;
    }

    public String getsF0() {
        return sF0;
    }

    public String getsF1() {
        return sF1;
    }

    public String getsE() {
        return sE;
    }

    public String getSignedPseudonym() {
        return signedPseudonym;
    }

    public String getFlag() {
        return flag;
    }

    public void readDAASignatureFile() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(TopographiaDefaultOptionValues.DEF_DAA_SIGNATURE));

        int zetaLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        zeta = reader.readLine().substring(0, zetaLength * 2);

        int capitalTLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        capitalT = reader.readLine().substring(0, capitalTLength * 2);

        int challengeLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        challenge = reader.readLine().substring(0, challengeLength * 2);

        int nonceTpmLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        nonceTpm = reader.readLine().substring(0, nonceTpmLength * 2);

        int sVLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        sV = reader.readLine().substring(0, sVLength * 2);

        int sF0Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        sF0 = reader.readLine().substring(0, sF0Length * 2);

        int sF1Length = Integer.parseInt(reader.readLine().split(" ")[0]);
        sF1 = reader.readLine().substring(0, sF1Length * 2);

        int sELength = Integer.parseInt(reader.readLine().split(" ")[0]);
        sE = reader.readLine().substring(0, sELength * 2);

        int signedPseudonymLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        signedPseudonym = reader.readLine().substring(0, signedPseudonymLength * 2);

        int flagLength = Integer.parseInt(reader.readLine().split(" ")[0]);
        flag = reader.readLine().substring(0, flagLength);

        reader.close();
    }
}
