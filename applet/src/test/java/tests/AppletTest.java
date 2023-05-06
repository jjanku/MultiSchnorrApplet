package tests;

import static org.junit.jupiter.api.Assertions.*;

import applet.Protocol;
import cz.muni.fi.crocs.rcard.client.CardType;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class AppletTest extends BaseTest {
    private final SecureRandom rng = new SecureRandom();
    private final MessageDigest md = MessageDigest.getInstance("SHA-256");
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

    @Test
    public void dkgen() throws  Exception {
        BigInteger x2 = ECParams.randomMult();
        PossessedKey pk2 = new PossessedKey(x2);
        assertTrue(pk2.verify());
        PossessedKey pk1 = app.dkgen(pk2);

        assertEquals(pk1.point, app.getIdentity());
        assertTrue(pk1.verify());
        ECPoint X = pk1.point.multiply(x2);
        assertEquals(X, app.getGroup());
    }

    @Test
    public void sign() throws Exception {
        ECPoint X, R, R1;
        BigInteger s, c;
        byte[] msg, digest;

        PossessedKey pk2 = new PossessedKey(ECParams.randomMult());
        PossessedKey pk1 = app.dkgen(pk2);
        X = app.getGroup();

        R1 = app.commit(false);
        msg = new byte[Protocol.MSG_LEN];
        rng.nextBytes(msg);
        R = ECParams.randomPoint();
        s = app.sign(R, msg);

        md.update(R.getEncoded(false));
        md.update(X.getEncoded(false));
        digest = md.digest(msg);
        c = new BigInteger(1, digest);
        assertEquals(ECParams.G.multiply(s), R1.add(pk1.point.multiply(c)));
    }

    @Test
    public void nonceReuse() throws Exception {
        byte[] msg = new byte[Protocol.MSG_LEN];
        app.commit(false);
        app.sign(ECParams.randomPoint(), msg);
        IsoCardException e = assertThrows(IsoCardException.class,
            () -> app.sign(ECParams.randomPoint(), msg));
        assertEquals(e.status, Protocol.ERR_COMMIT);
    }
}
