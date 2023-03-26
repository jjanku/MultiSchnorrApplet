package tests;

import applet.Protocol;
import cz.muni.fi.crocs.rcard.client.CardType;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class PerformanceTest extends BaseTest {
    public static final int REPS = 100;

    private final SecureRandom rng = new SecureRandom();
    private final MessageDigest md = MessageDigest.getInstance("SHA-256");
    private AppletConnection app;
    private CSVPrinter csv;

    public PerformanceTest() throws Exception {
        // Change card type here if you want to use physical card
        setCardType(CardType.JCARDSIMLOCAL);
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        app = new AppletConnection(connect());
        // ensures possible applet initialization
        // does not affect the measurement
        app.getIdentity();
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        app.close();
        app = null;
        if (csv != null) {
            csv.close();
            csv = null;
        }
    }

    private void test(boolean prob) throws Exception {
        csv = new CSVPrinter(
            Files.newBufferedWriter(Paths.get("measurements.csv")),
            CSVFormat.DEFAULT
        );

        String[] baseCols = {
            "Kgen", "Dkgen", "Commit", "Sign", "SignCommit"};
        String[] probCols = {
            "SignCommitProb", "CommitProbTotal", "SignProbTotal", "ProbTries"};
        Stream<String> cols = Stream.concat(
            Stream.of(baseCols),
            prob ? Stream.of(probCols) : Stream.empty()
        );
        csv.printRecord(cols);

        for (int i = 0; i < REPS; ++i) {
            BigInteger x2 = ECParams.randomMult();
            PossessedKey pk2 = new PossessedKey(x2);
            ECPoint R = ECParams.randomPoint();
            byte[] msg = new byte[Protocol.MSG_LEN];
            rng.nextBytes(msg);

            app.kgen();
            csv.print(app.getCommandTimeNano());

            PossessedKey pk1 = app.dkgen(pk2);
            csv.print(app.getCommandTimeNano());
            ECPoint X = pk1.point.multiply(x2);

            app.commit(false);
            csv.print(app.getCommandTimeNano());
            app.sign(R, msg);
            csv.print(app.getCommandTimeNano());

            // doesn't matter whether the result is correct here,
            // we just need the card to commit to some value
            app.commit(true);
            app.signCommit(R, msg, false);
            csv.print(app.getCommandTimeNano());

            if (prob) {
                app.signCommit(R, msg, true);
                csv.print(app.getCommandTimeNano());

                long tCommitProbTotal = 0, tSignProbTotal = 0;
                int nTries = 0;

                for (boolean success = false; !success; ++nTries) {
                    ECPoint R1 = app.commit(true);
                    tCommitProbTotal += app.getCommandTimeNano();
                    R = ECParams.randomPoint();
                    BigInteger s = app.sign(R, msg);
                    tSignProbTotal += app.getCommandTimeNano();

                    md.update(R.getEncoded(false));
                    md.update(X.getEncoded(false));
                    BigInteger c = new BigInteger(1, md.digest(msg));
                    ECPoint sG = ECParams.G.multiply(s);
                    ECPoint cX1 = pk1.point.multiply(c);

                    if (sG.equals(cX1.add(R1)))
                        success = true;
                    else
                        // ensures that the result is not skewed
                        // if the applet implementation is faulty
                        assertEquals(sG, cX1.subtract(R1));
                }

                csv.print(tCommitProbTotal);
                csv.print(tSignProbTotal);
                csv.print(nTries);
            }

            csv.println();
            if (isPhysical())
                csv.flush();
        }
    }

    @Test
    public void full() throws Exception {
        test(true);
    }

    @Test
    public void noProb() throws Exception {
        test(false);
    }
}
