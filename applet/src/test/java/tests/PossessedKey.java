package tests;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class PossessedKey {
    public final ECPoint point;
    public final byte[] pop;

    public PossessedKey(ECPoint point, byte[] pop) {
        this.point = point;
        this.pop = pop;
    }

    public PossessedKey(BigInteger secret) {
        point = ECParams.G.multiply(secret);

        DSADigestSigner signer = getSigner();
        signer.init(true, new ECPrivateKeyParameters(secret, ECParams.params));
        byte[] pointEnc = point.getEncoded(false);
        signer.update(pointEnc, 0, pointEnc.length);
        pop = signer.generateSignature();
    }

    public boolean verify() {
        DSADigestSigner signer = getSigner();
        signer.init(false, new ECPublicKeyParameters(point, ECParams.params));
        byte[] pointEnc = point.getEncoded(false);
        signer.update(pointEnc, 0, pointEnc.length);
        return signer.verifySignature(pop);
    }

    private DSADigestSigner getSigner() {
        return new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
    }
}
