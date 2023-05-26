package uk.ac.ncl.cascade.daa.sign;

import uk.ac.ncl.cascade.daa.DAALibs;

public class DAASignLib implements DAALibs {
    public static final String TOPOGRAPHIA_DAA_SIGN = "topographia_daa_sign";

    @Override
    public void loadLib() {
        try {
            System.loadLibrary(TOPOGRAPHIA_DAA_SIGN);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    @Override
    public String executeDAA() {
        String[] str = {" "};
        topographia_daa_sign.tp_daa_sign(str);
        String res = topographia_daa_sign.getSignResult();
        System.out.println("res : " + res);
        return res;
    }
}
