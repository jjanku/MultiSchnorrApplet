package applet;

import applet.jcmathlib.*;
import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public class MainApplet extends Applet implements MultiSelectable {
    private byte[] ram;
    private RandomData rng;
    private MessageDigest md;
    private Signature ecdsa;

    private ECConfig ecc;
    private ECCurve curve;

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
        ecc = new ECConfig(SecP256k1.KEY_LENGTH);
        curve = new ECCurve(false, SecP256k1.p, SecP256k1.a, SecP256k1.b,
            SecP256k1.G, SecP256k1.r);

        ram = JCSystem.makeTransientByteArray(curve.POINT_SIZE,
            JCSystem.CLEAR_ON_DESELECT);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        order = new BigNat(curve.r, ecc.rm);
        identityPriv = new BigNat(order.length(),
            JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
        noncePriv = new BigNat(order.length(),
            JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
        signature = new BigNat(order.length(),
            JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);

        identityPub = new ECPoint(curve, ecc.rm);
        noncePub = new ECPoint(curve, ecc.rm);
        groupPub = new ECPoint(curve, ecc.rm);

        setRandomPoint(identityPriv, identityPub);
        groupPub.copy(identityPub);

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

    public boolean select(boolean b) {
        if (initialized)
            ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {
    }

    private void setRandomPoint(BigNat scalar, ECPoint point) {
        rng.generateData(ram, (short) 0, order.length());
        scalar.from_byte_array(order.length(), (short) 0, ram, (short) 0);
        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(scalar);
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
        // TODO: store it in an array?
        ecdsa.init(curve.bignatAsPrivateKey(identityPriv), Signature.MODE_SIGN);
        short sigLen = ecdsa.sign(buf, (short) 0, curve.POINT_SIZE,
            buf, curve.POINT_SIZE);
        apdu.setOutgoingAndSend((short) 0, (short) (curve.POINT_SIZE + sigLen));
    }

    private short commit(byte[] buf, short off, boolean prob) {
        rng.generateData(ram, (short) 0, order.length());
        noncePriv.from_byte_array(order.length(), (short) 0, ram, (short) 0);
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
        groupPub.getW(ram, (short) 0);
        md.update(ram, (short) 0, curve.POINT_SIZE);
        md.update(buf, (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE),
            Protocol.MSG_LEN);
        short hashLen = md.doFinal(buf, ISO7816.OFFSET_CDATA, curve.POINT_SIZE,
            ram, (short) 0);

        signature.erase();
        signature.from_byte_array(hashLen, (short) 0, ram, (short) 0);
        signature.mod_mult(signature, identityPriv, order);
        signature.mod_add(noncePriv, order);
        commited = false;

        signature.copy_to_buffer(buf, (short) 0);
        short len = order.length();
        if (commit)
            len += commit(buf, len, prob);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
