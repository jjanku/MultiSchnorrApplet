package applet;

import applet.jcmathlib.*;
import javacard.framework.*;

public class MainApplet extends Applet implements MultiSelectable {
    private ECConfig ecc;
    private ECCurve curve;

    private boolean initialized = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength).register();
    }

    public MainApplet(byte[] buffer, short offset, byte length) {
        OperationSupport support = OperationSupport.getInstance();
        support.setCard(OperationSupport.SIMULATOR);
        if (!support.DEFERRED_INITIALIZATION)
            initialize();
    }

    private void initialize() {
        ecc = new ECConfig(SecP256k1.KEY_LENGTH);
        curve = new ECCurve(false, SecP256k1.p, SecP256k1.a, SecP256k1.b,
            SecP256k1.G, SecP256k1.r);
        initialized = true;
    }

    public void process(APDU apdu) {
        if (!initialized)
            initialize();
    }

    public boolean select(boolean b) {
        if (initialized)
            ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {
    }
}
