package tests;

import applet.Protocol;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletConnection {
    private final CardManager card;

    public AppletConnection(CardManager card) {
        this.card = card;
    }

    public void close() throws CardException {
        card.disconnect(true);
    }

    private static ECPoint decodePoint(byte[] data) {
        return ECParams.curve.decodePoint(data);
    }

    private byte[] command(byte ins, int p1, byte[] data) throws CardException {
        ResponseAPDU resp = card.transmit(
            new CommandAPDU(Protocol.CLA, ins, p1, 0, data));
        if (resp.getSW() != 0x9000)
            throw new IsoCardException(resp.getSW());
        return resp.getData();
    }

    public long getCommandTimeNano() {
        return card.getLastTransmitTimeNano();
    }

    public ECPoint getIdentity() throws CardException {
        byte[] data = command(Protocol.INS_GET_IDENTITY, 0, null);
        return decodePoint(data);
    }

    public ECPoint getGroup() throws CardException {
        byte[] data = command(Protocol.INS_GET_GROUP, 0, null);
        return decodePoint(data);
    }

    public void kgen() throws CardException {
        command(Protocol.INS_KGEN, 0, null);
    }

    public PossessedKey dkgen(PossessedKey key) throws CardException {
        byte[] pointEnc = key.point.getEncoded(false);
        byte[] data = command(Protocol.INS_DKGEN, 0,
            Arrays.concatenate(pointEnc, key.pop));
        return new PossessedKey(
            decodePoint(Arrays.copyOfRange(data, 0, pointEnc.length)),
            Arrays.copyOfRange(data, pointEnc.length, data.length)
        );
    }

    public ECPoint commit(boolean prob) throws CardException {
        byte[] data = command(Protocol.INS_COMMIT, prob ? 1 : 0, null);
        return decodePoint(data);
    }

    public BigInteger sign(ECPoint nonce, byte[] message) throws CardException {
        byte[] data = command(Protocol.INS_SIGN, 0,
            Arrays.concatenate(nonce.getEncoded(false), message));
        return new BigInteger(1, data);
    }

    public Pair<BigInteger, ECPoint> signCommit(
        ECPoint nonce, byte[] message, boolean prob
    ) throws CardException {
        byte[] data = command(Protocol.INS_SIGN_COMMIT, prob ? 1 : 0,
            Arrays.concatenate(nonce.getEncoded(false), message));
        int sigLen = BigIntegers.getUnsignedByteLength(ECParams.order);
        return new ImmutablePair<>(
            new BigInteger(1, Arrays.copyOfRange(data, 0, sigLen)),
            decodePoint(Arrays.copyOfRange(data, sigLen, data.length))
        );
    }
}
