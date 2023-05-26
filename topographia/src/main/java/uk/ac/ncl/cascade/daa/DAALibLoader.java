package uk.ac.ncl.cascade.daa;

import uk.ac.ncl.cascade.daa.join.DAAJoinLib;
import uk.ac.ncl.cascade.daa.sign.DAASignLib;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

public class DAALibLoader {

    public DAALibLoader() {

    }

    public static DAALibs loadLib(String libName){
        Assert.notNull(libName, "name for native code library is empty");

        switch (libName) {
            case "topographia_daa_join":
                return new DAAJoinLib();
            case "topographia_daa_sign":
                return new DAASignLib();
            default:
                throw new IllegalArgumentException("Unknown library name "+ libName);
        }
    }

}

