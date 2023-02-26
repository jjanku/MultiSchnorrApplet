package applet;

import applet.jcmathlib.*;
import javacard.framework.*;
import javacard.security.CryptoException;

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
        if (selectingApplet())
            return;

        if (!initialized)
            initialize();

        byte[] buf = apdu.getBuffer();

        if(buf[ISO7816.OFFSET_CLA] != Protocol.CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        try {
            switch (buf[ISO7816.OFFSET_INS]) {
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e;
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ReturnCodes.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(ReturnCodes.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(ReturnCodes.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(ReturnCodes.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(ReturnCodes.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short)
                (ReturnCodes.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short)
                (ReturnCodes.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short)
                (ReturnCodes.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short)
                (ReturnCodes.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short)
                (ReturnCodes.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(ReturnCodes.SW_Exception);
        }
    }

    public boolean select(boolean b) {
        if (initialized)
            ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {
    }
}
