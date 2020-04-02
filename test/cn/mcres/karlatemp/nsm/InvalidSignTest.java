/*
 * Copyright (c) 2018-2020 Karlatemp. All rights reserved.
 * @author Karlatemp <karlatemp@vip.qq.com> <https://github.com/Karlatemp>
 * @create 2020/04/02 21:03:47
 *
 * NetworkSecurityManager/NetworkSecurityManager/InvalidSignTest.java
 */

package cn.mcres.karlatemp.nsm;

import cn.mcres.karlatemp.mxlib.util.RAFOutputStream;
import kotlin.Unit;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.zip.ZipFile;

public class InvalidSignTest {
    public static void main(String[] args) throws Throwable {
        final KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = rsa.generateKeyPair();

        X500Principal serverSubjectName = new X500Principal("CN=OrganizationName");
        SimpleDateFormat format = new SimpleDateFormat("yyyy/MM/dd");
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.setSerialNumber(new BigInteger("123456789"));
        generator.setIssuerDN(serverSubjectName);
        generator.setNotBefore(format.parse("2020/04/02"));
        generator.setNotAfter(format.parse("2020/12/02"));
        generator.setSubjectDN(serverSubjectName);
        generator.setPublicKey(pair.getPublic());
        generator.setSignatureAlgorithm("MD5withRSA");


        final X509Certificate certificate = generator.generate(pair.getPrivate());

        System.out.println("Encoding.....");
        try (RAFOutputStream raf = new RAFOutputStream(new RandomAccessFile("out/mbl-invalid.jar", "rw"))) {
            SecurityManagerEncoder.INSTANCE.encode(
                    new ZipFile("G:\\IDEAProjects\\MXLib\\dist\\MXBukkitLib.jar"),
                    raf,
                    certificate,
                    pair.getPrivate(),
                    Collections.emptyList()
            );
        }

        System.out.println("Checking");
        if (!NetworkSecurityManager.INSTANCE.check(
                new ZipFile("out/mbl-invalid.jar"),
                (X509Certificate) NetworkSecurityManager.getX509Factory().generateCertificate(
                        new FileInputStream("G:\\SSL\\Karlatemp.ssl.crt")
                ), Collections.emptyList(), u -> {
                    System.out.println(u);
                    return Unit.INSTANCE;
                }
        )) {
            System.err.println("没有签名");
        }
    }
}
