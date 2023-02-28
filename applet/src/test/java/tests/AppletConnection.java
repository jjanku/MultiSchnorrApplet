package tests;

import applet.Protocol;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletConnection {
    private final CardManager card;

    public final ECNamedCurveParameterSpec params;
    public final ECCurve curve;
    public final ECPoint G;

    public AppletConnection(CardManager card) {
        this.card = card;
        params = ECNamedCurveTable.getParameterSpec("secp256k1");
        curve = params.getCurve();
        G = params.getG();
    }

    public void close() throws CardException {
        card.disconnect(true);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        return ByteBuffer.allocate(a.length + b.length).put(a).put(b).array();
    }

    private byte[] command(byte ins, byte[] data) throws CardException {
        ResponseAPDU resp = card.transmit(
            new CommandAPDU(Protocol.CLA, ins, 0, 0, data));
        if (resp.getSW() != 0x9000)
            throw new IsoCardException(resp.getSW());
        return resp.getData();
    }

    public ECPoint getIdentity() throws CardException {
        byte[] data = command(Protocol.INS_GET_IDENTITY, null);
        return curve.decodePoint(data);
    }

    public ECPoint getGroup() throws  CardException {
        byte[] data = command(Protocol.INS_GET_GROUP, null);
        return curve.decodePoint(data);
    }

    public ECPoint dkgen(ECPoint point) throws CardException {
        byte[] data  = command(Protocol.INS_DKGEN, point.getEncoded(false));
        return curve.decodePoint(data);
    }

    public ECPoint commit() throws CardException {
        byte[] data = command(Protocol.INS_COMMIT, null);
        return curve.decodePoint(data);
    }

    public BigInteger sign(ECPoint nonce, byte[] message) throws CardException {
        byte[] data = command(Protocol.INS_SIGN,
            concat(nonce.getEncoded(false), message));
        return new BigInteger(1, data);
    }
}
