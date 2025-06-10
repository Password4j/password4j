package com.password4j;

import com.password4j.types.Argon2;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.lang.reflect.Field;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class IssuesTest
{

    /**
     * @see <a href="https://github.com/Password4j/password4j/issues/92">issue #92</a>
     */
    @Test
    public void issue92()
    {
        String hash = "$argon2id$v=19$m=16384,t=2,p=1$nlm7oNI5zquzSYkyby6oVw$JOkJAYrDB0i2gmiJrXC6o2r+u1rszCm/RO9gIQtnxlY";
        String plain = "Test123!";
        Argon2Function function = Argon2Function.getInstanceFromHash(hash);

        boolean verified = Password.check(plain, hash).with(function);
        Hash newHash = Password.hash(plain).addSalt("Y9ΫI2o.W").with(function);
        boolean verified2 = Password.check(plain, newHash);

        assertTrue(verified);
        assertTrue(verified2);
        assertEquals("$argon2id$v=19$m=16384,t=2,p=1$WTnOq0kyby5X$SewIdM+Ywctw0lfNQ0xKYoUIlyRs3qF+gVmEVtpdmyg", newHash.getResult());
    }


    /**
     * @see <a href="https://github.com/Password4j/password4j/issues/99">issue #99</a>
     */
    @Test
    public void issue99()
    {
        int memory          = 65536;
        int iterations      = 2;
        int parallelism     = 3;
        int outputLength    = 32;
        int version         = 0x13;
        byte[] salt         =
                {
                        (byte) 0x6b, (byte) 0x25, (byte) 0xc9, (byte) 0xd7, (byte) 0x0e, (byte) 0x5c, (byte) 0x19, (byte) 0xac,
                        (byte) 0x51, (byte) 0x74, (byte) 0xd7, (byte) 0x74, (byte) 0x53, (byte) 0xad, (byte) 0x23, (byte) 0x70,
                        (byte) 0x15, (byte) 0x27, (byte) 0x56, (byte) 0x2e, (byte) 0x02, (byte) 0xb8, (byte) 0xec, (byte) 0x5c,
                        (byte) 0xac, (byte) 0x89, (byte) 0x2d, (byte) 0xc3, (byte) 0xe4, (byte) 0xb5, (byte) 0x1c, (byte) 0x12
                };
        byte[] password="Test".getBytes();
        Argon2 type = Argon2.ID;
        Argon2Function instance=Argon2Function.getInstance(memory, iterations, parallelism, outputLength, type, version);

        Hash hash = instance.hash(password, salt);


        String expResult = "cbcfdee482c233e525ca405c7014e89cd33142758a2f1d23c420690f950c988c";
        assertEquals(expResult, printBytesToString(hash.getBytes()));
    }

    /**
     * @see <a href="https://github.com/Password4j/password4j/issues/93">issue #93</a>
     */
    @Test
    public void issue93()
    {
        String hash = "$argon2id$v=19$m=16384,t=2,p=1$nlm7oNI5zquzSYkyby6oVw$JOkJAYrDB0i2gmiJrXC6o2r+u1rszCm/RO9gIQtnxlY";
        Argon2Function function = Argon2Function.getInstanceFromHash(hash);

        boolean test1 = Password.check("Test123!", hash).with(function);
        assertTrue(test1);

        boolean test2 = function.check("Test123!", hash);
        assertTrue(test2);
    }


    /**
     * @see <a href="https://github.com/Password4j/password4j/issues/120">issue #120</a>
     */
    @Test(expected = Test.None.class)
    public void issue120()
    {
        // GIVEN
        String name = "issue120FakeProvider";
        Provider emptyProvider = new Provider(name, 1, "info")
        {
            @Override
            public synchronized Set<Service> getServices()
            {
                return null;
            }
        };
        Security.addProvider(emptyProvider);

        // WHEN
        Password.hash("hash");

        // THEN
        Security.removeProvider(name);
    }


    /**
     * @see <a href="https://github.com/Password4j/password4j/issues/126">issue #126</a>
     */
    @Test
    public void issue126()
    {
        byte[] hashBytes = Password.hash("’(っ＾▿＾)۶\uD83C\uDF78\uD83C\uDF1F\uD83C\uDF7A٩(˘◡˘ ) ❌❌ ❌❌❌")
                .addSalt("\uD83E\uDDC2")
                .withScrypt()
                .getBytes();

        Assert.assertEquals("827b022b411e712e5ae4855d8c71cb047d882b2457120d1019974d17dcf6f1bf59644d9a93e470ab14ee5f7a88ae9b0140d2db121de58f6d830fc9c16c82f212", printBytesToString(hashBytes));


        hashBytes = Password.hash("ŸŁĀPRČ")
                .addSalt("ŸŁĀPRČAA")
                .withArgon2()
                .getBytes();

        Assert.assertEquals("59dedcf45d7a8604926ca66f6abe3990ce8b6ba108f535836fa18e95b7d94e9f56301e422c1d487dd06dc26061261402a5f7fe912bd545b6aeec866fec74df81", printBytesToString(hashBytes));

    }

    @Test
    public void issue162() throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException
    {
        // GIVEN
        String versionProperty = System.getProperty("java.specification.version");
        if(!versionProperty.contains("."))
        {
            int major = Integer.parseInt(versionProperty);
            Assume.assumeTrue(major < 17 );
        }

        Argon2Function argon2Function = Argon2Function.getInstance(1, 1, 2, 32, Argon2.I);

        // WHEN
        Password.hash("password").with(argon2Function);

        // THEN
        Class<?> clazz = Class.forName("java.lang.ApplicationShutdownHooks");
        Field field = clazz.getDeclaredField("hooks");
        field.setAccessible(true);
        List<Thread> hooks = ((Map<Thread, Thread>) field.get(null)).values().stream().filter(thread -> "password4j-shutdownhook".equals(thread.getName())).collect(Collectors.toList());

        Assert.assertFalse(hooks.isEmpty());
    }


    private static String printBytesToString(byte[] bytes)
    {
        StringBuilder byteString= new StringBuilder();
        if (bytes!=null)
        {
            for (byte aByte : bytes)
            {
                byteString.append(String.format("%02x", aByte));
            }
        }
        else
        {
            byteString = new StringBuilder("-");
        }
        return byteString.toString();
    }

    /**
     * <h2>Issue #163: Tomcat Thread Leak Prevention</h2>
     *
     * <p><strong>Problem:</strong> Tomcat was reporting thread leak warnings:</p>
     * <blockquote>
     * "The web application appears to have started a thread named [password4j-worker-X]
     * but has failed to stop it. This is very likely to create a memory leak."
     * </blockquote>
     *
     * <p><strong>Root Cause:</strong> Non-daemon threads prevent JVM shutdown and cause
     * application server warnings when web applications are undeployed.</p>
     *
     * <p><strong>Solution:</strong> Changed <code>thread.setDaemon(false)</code> to
     * <code>thread.setDaemon(true)</code> in <code>Utils.createExecutorService()</code></p>
     *
     * <p><strong>Impact:</strong> Daemon threads automatically terminate when the main
     * application shuts down, preventing memory leaks in containerized environments.</p>
     *
     * @see <a href="https://github.com/Password4j/password4j/issues/163" target="_blank">GitHub Issue #163</a>
     * @see Utils#createExecutorService()
     * @see <a href="https://docs.oracle.com/javase/tutorial/essential/concurrency/daemon.html" target="_blank">Oracle: Daemon Threads</a>
     * @since 1.8.1
     * @category Threading
     * @category MemoryLeak
     */

    @Test
    public void issue163() {
        final String plainText = "The quick brown fox jumps over the lazy dog";
        final String hash = Password.hash(plainText)
                                    .withArgon2()
                                    .getResult();
        assertNotNull("Password hashing should work", hash);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        boolean foundWorkerThread = false;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().startsWith("password4j-worker-")) {
                foundWorkerThread = true;

                // THE FIX: This thread MUST be daemon to prevent Tomcat memory leak warning
                final String assertionMessage = "Thread " + thread.getName() + " must be daemon thread to prevent Tomcat leak warning";
                assertTrue(assertionMessage, thread.isDaemon());
            }
        }
        assertTrue("Should have found at least one password4j-worker thread", foundWorkerThread);
    }

}
