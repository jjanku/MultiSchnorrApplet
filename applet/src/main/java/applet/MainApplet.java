package applet;

import applet.jcmathlib.*;
import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public class MainApplet extends Applet {
    private byte[] ram;
    private RandomData rng;
    private MessageDigest md;
    private Signature ecdsa;

    private ResourceManager rm;
    private ECCurve curve;

    private short identityPopLen;
    private byte[] identityPop;
    private BigNat order, identityPriv, noncePriv, signature;
    private ECPoint identityPub, noncePub, groupPub;

    private boolean initialized = false, commited = false;

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
        rm = new ResourceManager((short) 256);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b,
            SecP256k1.G, SecP256k1.r, rm);

        ram = JCSystem.makeTransientByteArray(curve.POINT_SIZE,
            JCSystem.CLEAR_ON_DESELECT);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        ecdsa.init(curve.disposablePriv, Signature.MODE_SIGN);
        identityPop = new byte[ecdsa.getLength()];

        order = new BigNat((short) curve.r.length,
            JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        order.fromByteArray(curve.r, (short) 0, (short) curve.r.length);
        identityPriv = new BigNat(order.length(),
            JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        noncePriv = new BigNat(order.length(),
            JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        signature = new BigNat((short) (order.length() + 1),
            JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);

        identityPub = new ECPoint(curve);
        noncePub = new ECPoint(curve);
        groupPub = new ECPoint(curve);

        kgen();

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
                case Protocol.INS_GET_IDENTITY:
                    getIdentity(apdu);
                    break;
                case Protocol.INS_GET_GROUP:
                    getGroup(apdu);
                    break;
                case Protocol.INS_KGEN:
                    kgen();
                    break;
                case Protocol.INS_DKGEN:
                    dkgen(apdu);
                    break;
                case Protocol.INS_COMMIT:
                    commit(apdu);
                    break;
                case Protocol.INS_SIGN:
                    sign(apdu, false);
                    break;
                case Protocol.INS_SIGN_COMMIT:
                    sign(apdu, true);
                    break;

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

    public boolean select() {
        if (curve != null)
            curve.updateAfterReset();
        return true;
    }

    private void kgen() {
        rng.generateData(ram, (short) 0, order.length());
        identityPriv.fromByteArray(ram, (short) 0, order.length());
        identityPub.setW(curve.G, (short) 0, curve.POINT_SIZE);
        identityPub.multiplication(identityPriv);

        curve.disposablePriv.setG(curve.G, (short) 0, curve.POINT_SIZE);
        identityPriv.copyToByteArray(ram, (short) 0);
        curve.disposablePriv.setS(ram, (short) 0, identityPriv.length());
        identityPub.getW(ram, (short) 0);
        ecdsa.init(curve.disposablePriv, Signature.MODE_SIGN);
        identityPopLen = ecdsa.sign(ram, (short) 0, curve.POINT_SIZE,
            identityPop, (short) 0);

        groupPub.copy(identityPub);
        commited = false;
    }

    private void sendPoint(APDU apdu, ECPoint point) {
        point.getW(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void getIdentity(APDU apdu) {
        sendPoint(apdu, identityPub);
    }

    private void getGroup(APDU apdu) {
        sendPoint(apdu, groupPub);
    }

    private void dkgen(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen < curve.POINT_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        groupPub.setW(buf, ISO7816.OFFSET_CDATA, curve.POINT_SIZE);
        ecdsa.init(groupPub.asPublicKey(), Signature.MODE_VERIFY);
        boolean verifies = ecdsa.verify(
            buf,
            ISO7816.OFFSET_CDATA,
            curve.POINT_SIZE,
            buf,
            (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE),
            (short) (dataLen - curve.POINT_SIZE)
        );
        if (!verifies)
            ISOException.throwIt(Protocol.ERR_POP);

        groupPub.multiplication(identityPriv);

        identityPub.getW(buf, (short) 0);
        Util.arrayCopyNonAtomic(identityPop, (short) 0, buf, curve.POINT_SIZE,
            (short) identityPopLen);
        apdu.setOutgoingAndSend(
            (short) 0, (short) (curve.POINT_SIZE + identityPopLen));
    }

    private short commit(byte[] buf, short off, boolean prob) {
        rng.generateData(ram, (short) 0, order.length());
        noncePriv.fromByteArray(ram, (short) 0, order.length());
        noncePub.setW(curve.G, (short) 0, curve.POINT_SIZE);
        short len;
        if (!OperationSupport.getInstance().EC_HW_XY && prob) {
            noncePub.multXKA(noncePriv, buf, (short) (off + 1));
            // guess the y-coordinate, 1/2 success probability
            buf[off] = 0x02;
            len = (short) (curve.COORD_SIZE + 1);
        } else {
            noncePub.multiplication(noncePriv);
            noncePub.getW(buf, off);
            len = curve.POINT_SIZE;
        }
        commited = true;
        return len;
    }

    private void commit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        boolean prob = buf[ISO7816.OFFSET_P1] != 0;
        short len = commit(buf, (short) 0, prob);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void sign(APDU apdu, boolean commit) {
        if (!commited)
            ISOException.throwIt(Protocol.ERR_COMMIT);

        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != (short) (curve.POINT_SIZE + Protocol.MSG_LEN))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buf = apdu.getBuffer();
        boolean prob = buf[ISO7816.OFFSET_P1] != 0;

        // check the group nonce is a valid point on the curve
        noncePub.setW(buf, ISO7816.OFFSET_CDATA, curve.POINT_SIZE);

        md.reset();
        md.update(buf, ISO7816.OFFSET_CDATA, curve.POINT_SIZE);
        groupPub.getW(ram, (short) 0);
        md.update(ram, (short) 0, curve.POINT_SIZE);
        short hashLen = md.doFinal(
            buf, (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE),
                Protocol.MSG_LEN,
            ram, (short) 0
        );

        // assert hashLen <= order.length()
        signature.fromByteArray(ram, (short) 0, hashLen);
        signature.modMult(signature, identityPriv, order);
        signature.modAdd(noncePriv, order);
        commited = false;

        short len = order.length();
        signature.prependZeros(len, buf, (short) 0);
        if (commit)
            len += commit(buf, len, prob);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
