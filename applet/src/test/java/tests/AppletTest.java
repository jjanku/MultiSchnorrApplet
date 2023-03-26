package tests;

import static org.junit.jupiter.api.Assertions.*;

import applet.Protocol;
import cz.muni.fi.crocs.rcard.client.CardType;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class AppletTest extends BaseTest {
    private final Provider bc = new BouncyCastleProvider();
    private final SecureRandom rng = new SecureRandom();
    private final MessageDigest md = MessageDigest.getInstance("SHA-256");
    private final KeyFactory keyFactory = KeyFactory.getInstance("EC", bc);
    private final Signature ecdsa = Signature.getInstance("SHA256withECDSA", bc);
    private AppletConnection app;

    public AppletTest() throws Exception {
        // Change card type here if you want to use physical card
        setCardType(CardType.JCARDSIMLOCAL);
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        app = new AppletConnection(connect());
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        app.close();
        app = null;
    }

    private PossessedKey generateKey() throws Exception {
        BigInteger x = ECParams.randomMult();
        ECPoint X = ECParams.G.multiply(x);

        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(x, ECParams.params);
        PrivateKey priv = keyFactory.generatePrivate(keySpec);
        ecdsa.initSign(priv);
        ecdsa.update(X.getEncoded(false));
        byte[] pop = ecdsa.sign();

        return new PossessedKey(x, X, pop);
    }

    private boolean verifyKey(PossessedKey key) throws Exception {
        ECPublicKeySpec keySpec = new ECPublicKeySpec(key.point, ECParams.params);
        PublicKey pub = keyFactory.generatePublic(keySpec);
        ecdsa.initVerify(pub);
        ecdsa.update(key.point.getEncoded(false));
        return ecdsa.verify(key.pop);
    }

    @Test
    public void dkgen() throws  Exception {
        PossessedKey pk2 = generateKey();
        assertTrue(verifyKey(pk2));
        PossessedKey pk1 = app.dkgen(pk2);

        assertEquals(pk1.point, app.getIdentity());
        assertTrue(verifyKey(pk1));
        ECPoint X = pk1.point.multiply(pk2.secret);
        assertEquals(X, app.getGroup());
    }

    @Test
    public void sign() throws Exception {
        ECPoint X, R, R1;
        BigInteger s, c;
        byte[] msg, digest;

        PossessedKey pk2 = generateKey();
        PossessedKey pk1 = app.dkgen(pk2);
        X = app.getGroup();

        R1 = app.commit();
        msg = new byte[Protocol.MSG_LEN];
        rng.nextBytes(msg);
        R = ECParams.randomPoint();
        s = app.sign(R, msg);

        md.update(X.getEncoded(false));
        md.update(msg);
        digest = md.digest(R.getEncoded(false));
        c = new BigInteger(1, digest);
        assertEquals(ECParams.G.multiply(s), R1.add(pk1.point.multiply(c)));
    }

    @Test
    public void nonceReuse() throws Exception {
        byte[] msg = new byte[Protocol.MSG_LEN];
        app.commit();
        app.sign(ECParams.randomPoint(), msg);
        IsoCardException e = assertThrows(IsoCardException.class,
            () -> app.sign(ECParams.randomPoint(), msg));
        assertEquals(e.status, Protocol.ERR_COMMIT);
    }
}
