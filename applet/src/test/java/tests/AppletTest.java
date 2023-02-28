package tests;

import static org.junit.jupiter.api.Assertions.*;

import applet.Protocol;
import cz.muni.fi.crocs.rcard.client.CardType;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.smartcardio.CardException;

public class AppletTest extends BaseTest {
    private final SecureRandom rng = new SecureRandom();
    private final MessageDigest md = MessageDigest.getInstance("SHA-256");
    private AppletConnection app;

    public AppletTest() throws NoSuchAlgorithmException {
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

    private BigInteger randomMult() {
        return BigIntegers.createRandomInRange(
            BigInteger.ONE, app.curve.getOrder(), rng);
    }

    private  ECPoint randomPoint() {
        return app.G.multiply(randomMult());
    }

    @Test
    public void dkgen() throws  Exception {
        ECPoint X, X1, X2;
        BigInteger x2;

        x2 = randomMult();
        X2 = app.G.multiply(x2);

        X1 = app.dkgen(X2);
        assertEquals(X1, app.getIdentity());
        X = X1.multiply(x2);
        assertEquals(X, app.getGroup());
    }

    @Test
    public void sign() throws Exception {
        ECPoint X, X1, R, R1;
        BigInteger s, c;
        byte[] msg, digest;

        X1 = app.dkgen(randomPoint());
        X = app.getGroup();

        R1 = app.commit();
        msg = new byte[Protocol.MSG_LEN];
        rng.nextBytes(msg);
        R = randomPoint();
        s = app.sign(R, msg);

        md.update(X.getEncoded(false));
        md.update(msg);
        digest = md.digest(R.getEncoded(false));
        c = new BigInteger(1, digest);
        assertEquals(app.G.multiply(s), R1.add(X1.multiply(c)));
    }

    @Test
    public void nonceReuse() throws Exception {
        byte[] msg = new byte[Protocol.MSG_LEN];
        app.commit();
        app.sign(randomPoint(), msg);
        IsoCardException e = assertThrows(IsoCardException.class,
            () -> app.sign(randomPoint(), msg));
        assertEquals(e.status, Protocol.ERR_COMMIT);
    }
}
