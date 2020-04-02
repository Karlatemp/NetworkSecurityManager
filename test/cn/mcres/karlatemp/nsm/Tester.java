/*
 * Copyright (c) 2018-2020 Karlatemp. All rights reserved.
 * @author Karlatemp <karlatemp@vip.qq.com> <https://github.com/Karlatemp>
 * @create 2020/04/02 20:20:27
 *
 * NetworkSecurityManager/NetworkSecurityManager/Tester.java
 */

package cn.mcres.karlatemp.nsm;

import cn.mcres.karlatemp.mxlib.util.RAFOutputStream;
import kotlin.Unit;

import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.zip.ZipFile;

public class Tester {
    public static void main(String[] args) throws Throwable {

        System.out.println("Encoding.....");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new PKCS8EncodedKeySpec(
                KotUtils.INSTANCE.read("G:\\SSL\\Karlatemp.ssl.private.pem")
        );
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        try (RAFOutputStream raf = new RAFOutputStream(new RandomAccessFile("out/mbl.jar", "rw"))) {
            SecurityManagerEncoder.INSTANCE.encode(
                    new ZipFile("G:\\IDEAProjects\\MXLib\\dist\\MXBukkitLib.jar"),
                    raf,
                    (X509Certificate) NetworkSecurityManager.getX509Factory().generateCertificate(
                            new FileInputStream("G:\\SSL\\Karlatemp.ssl.crt")
                    ),
                    privateKey,
                    Collections.emptyList()
            );
        }

        System.out.println("Checking");
        if (!NetworkSecurityManager.INSTANCE.check(
                new ZipFile("out/mbl.jar"),
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
