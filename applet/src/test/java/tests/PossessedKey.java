package tests;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class PossessedKey {
    public final BigInteger secret;
    public final ECPoint point;
    public final byte[] pop;

    public PossessedKey(BigInteger secret, ECPoint point, byte[] pop) {
        this.secret = secret;
        this.point = point;
        this.pop = pop;
    }
}
