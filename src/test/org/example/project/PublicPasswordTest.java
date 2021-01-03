package org.example.project;

import com.password4j.*;
import org.junit.Assert;
import org.junit.Test;


public class PublicPasswordTest
{

    private static final TestSuite[] PBKDF2_TEST = new TestSuite[]{
            new TestSuite("r+bFUweFtsxrHGRTOEcxvV7kMu5Un9QvtmlXea2KHFv1neacSPd078QAfVKY+QM8AkHVq2kwXntk7O642DTP7A==", "password",
                    "salt", null, PBKDF2Function.getInstance(Hmac.SHA512, 1000, 512)),

            new TestSuite("x/daChKTPQGTKZrBsmPIqJ3KtqcaYni8FqdziEgPRw9gowIpZxfzW7UI8gqZj0pI5xChr5RDxjYjc8yMbucHHw==", "password",
                    "salt", "pepper", PBKDF2Function.getInstance(Hmac.SHA512, 1000, 512)),

            new TestSuite("EgvuM3qhGradmNwl2b1Z5uPnasY=", "123", "456", "",
                    PBKDF2Function.getInstance(Hmac.SHA1, 49999, 160)),

            new TestSuite("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "bc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "a",
                    BCryptFunction.getInstance(6)),

            new TestSuite("$2a$09$PVRpK74XnUl/dsFfw6YSsOgwnJ1N3b5jKgbR/qdqerkuIYMa2u6eG", "Password", "$2a$09$PVRpK74XnUl/dsFfw6YSsO", "my",
                    BCryptFunction.getInstance(9)),

            new TestSuite("$2a$07$W3mOfB5auMDG3EitumH0S.ffmkA.NZIOZFaXb15tPWQyqq0hDXiEC", "Alice", "$2a$07$W3mOfB5auMDG3EitumH0S.", null,
                    BCryptFunction.getInstance(7)),

            new TestSuite("$2a$14$7rdjAp2vQxO0hCK9GvniqeKURflehmGaW5C2CLOONKZauODS7xOGW", "password4j", "$2a$14$7rdjAp2vQxO0hCK9Gvniqe", null,
                    BCryptFunction.getInstance(14)),

            new TestSuite("$s0$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==", "word", "salt",
                    "pass", SCryptFunction.getInstance(16384, 8, 1)),

            new TestSuite("$s0$a0402$bm90UmFuZG9t$upriFfo7v+aAUqOKDpguh0duZlAHiKcQOLM0k/xFcBg7qfRcDfYLEZe/60+b+4NtA1M70LUI0IRY+3+ybuLMZg==", "known", "notRandom",
                    "un", SCryptFunction.getInstance(1024, 4, 2))
    };

    @Test
    public void test()
    {

        for (TestSuite test : PBKDF2_TEST)
        {
            Assert.assertEquals(test.hashingFunction.toString(), test.hash,
                    Password.hash(test.password).addSalt(test.salt).addPepper(test.pepper).with(test.hashingFunction)
                            .getResult());

            SecureString securePassword = new SecureString(test.password.toCharArray());
            Assert.assertEquals(test.hashingFunction.toString(), test.hash,
                    Password.hash(securePassword).addSalt(test.salt).addPepper(test.pepper).with(test.hashingFunction)
                            .getResult());

        }

    }

    @Test
    public void testUpdate()
    {

        for (TestSuite test : PBKDF2_TEST)
        {
            Assert.assertEquals(test.hashingFunction.toString(), test.hash,
                    Password.hash(test.password).addSalt(test.salt).addPepper(test.pepper).with(test.hashingFunction)
                            .getResult());

            HashUpdate update = Password.check(test.password, test.hash).addSalt(test.salt).addPepper(test.pepper).andUpdate().with(test.hashingFunction, test.hashingFunction);
            Assert.assertTrue(test.hashingFunction.toString(), update.isVerified());
            Assert.assertEquals(test.hashingFunction.toString(), Password.hash(test.password).addSalt(test.salt).addPepper(test.pepper).with(test.hashingFunction).getResult(), update.getHash().getResult());

        }

    }

    /**
     * Must compile.
     */
    @Test
    public void testAccessibility()
    {
        try
        {
            String password = "";
            String salt = "";
            int saltLength = 1;
            String pepper = "";

            HashBuilder hb = Password.hash(password);
            hb.addPepper(pepper);
            hb.addPepper();
            hb.addRandomSalt();
            hb.addRandomSalt(saltLength);
            hb.addSalt(salt);

            hb.withCompressedPBKDF2();
            hb.withSCrypt();
            hb.withBCrypt();
            hb.withPBKDF2();

            HashChecker hc = Password.check(password, password);
            hc.addPepper(pepper);
            hc.addPepper();
            hc.addSalt(salt);
            hc.withCompressedPBKDF2();
            hc.withSCrypt();
            hc.withBCrypt();
            hc.withPBKDF2();

            Hmac.SHA256.code();
            Hmac.values();
            Hmac.SHA1.bits();

            PBKDF2Function.getInstance(Hmac.SHA512, 1, 1);
            PBKDF2Function.getInstance(password, 1, 1);
            CompressedPBKDF2Function.getInstance(Hmac.SHA512, 1, 1);
            CompressedPBKDF2Function.getInstance(password, 1, 1);
            CompressedPBKDF2Function.getInstanceFromHash(password);

            BCryptFunction.getInstance(1);
            SCryptFunction.getInstance(2, 1, 1);
            SCryptFunction.getInstanceFromHash(password);

            SecureString s = new SecureString(new char[]{'a'});
            s.clear();
        }
        catch (Exception e)
        {
            //
        }
    }

    private static class TestSuite
    {
        private String hash;

        private String password;

        private String salt;

        private String pepper;

        private HashingFunction hashingFunction;

        TestSuite(String hash, String password, String salt, String pepper, HashingFunction hashingFunction)
        {
            this.hash = hash;
            this.password = password;
            this.salt = salt;
            this.pepper = pepper;
            this.hashingFunction = hashingFunction;
        }
    }

}
