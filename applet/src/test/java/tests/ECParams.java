package tests;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ECParams {
    public static final ECDomainParameters params =
        new ECDomainParameters(ECNamedCurveTable.getByName("secp256k1"));

    public static final ECCurve curve = params.getCurve();
    public static final ECPoint G = params.getG();
    public static final BigInteger order = params.getN();

    public static BigInteger randomMult() {
        return BigIntegers.createRandomInRange(
            BigInteger.ONE, ECParams.order, new SecureRandom());
    }

    public static ECPoint randomPoint() {
        return ECParams.G.multiply(randomMult());
    }
}
