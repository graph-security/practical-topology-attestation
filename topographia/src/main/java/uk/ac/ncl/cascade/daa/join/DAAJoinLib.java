package uk.ac.ncl.cascade.daa.join;

import uk.ac.ncl.cascade.daa.DAALibs;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.math.BigInteger;

public class DAAJoinLib implements DAALibs {

    public static final String TOPOGRAPHIA_DAA_JOIN = "topographia_daa_join";

    @Override
    public void loadLib() {
        try {
            System.loadLibrary(TOPOGRAPHIA_DAA_JOIN);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }

    }

    @Override
    public String executeDAA(){
        String[] str = {" "};
        topographia_daa_join.tp_daa_join(str);
        BigInteger bi = new BigInteger(topographia_daa_join.getNG(), 16);
        Assert.notNull(bi, "empty NG");
        System.out.println("bi biginteger: " + bi);
        System.out.println("bi hex: " + bi.toString(16));
        return bi.toString(16);
    }
}
