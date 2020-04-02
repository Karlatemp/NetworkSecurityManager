/*
 * Copyright (c) 2018-2020 Karlatemp. All rights reserved.
 * @author Karlatemp <karlatemp@vip.qq.com> <https://github.com/Karlatemp>
 * @create 2020/04/02 19:02:02
 *
 * NetworkSecurityManager/NetworkSecurityManager/NetworkSecurityManager.kt
 */

package cn.mcres.karlatemp.nsm

import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import java.util.zip.ZipFile


class SecurityException : RuntimeException()
object NetworkSecurityManager {
    @JvmStatic
    val x509Factory: CertificateFactory =
        CertificateFactory.getInstance("X.509") ?: throw ExceptionInInitializerError("Failed to load X.509 Factory")

    @Throws(SecurityException::class, IOException::class)
    fun check(
        zip: ZipFile,
        caRoot: X509Certificate,
        revoked: Collection<X509Certificate>,
        warning: (message: String) -> Unit
    ): Boolean {
        val stream = zip.getInputStream(zip.getEntry("NSM/x509") ?: return false) ?: return false
        val link: MutableList<String> = mutableListOf()
        stream.use {
            InputStreamReader(stream, StandardCharsets.UTF_8).use { reader ->
                reader.forEachLine { line ->
                    if (line.isEmpty()) return@forEachLine
                    link.add(line.trim())
                }
            }
        }
        val certs: MutableList<X509Certificate> = mutableListOf()
        link.forEach {
            (
                    zip.getInputStream(
                        zip.getEntry("NSM/cert/${it}.cert") ?: throw SecurityException("Failed to find $it")
                    ) ?: throw SecurityException("Failed to load $it")
                    ).use { cert ->
                certs.add(x509Factory.generateCertificate(cert) as X509Certificate)
            }
        }
        if (certs.isEmpty()) throw SecurityException("No Certificate found!")
        var last = caRoot
        for (c in certs) {
            if (c.issuerDN == last.subjectDN) {
                c.verify(last.publicKey)
                last = c
                if (revoked.contains(c)) throw SecurityException("Certificate has been revoked.")
            } else {
                throw SecurityException("Cannot check link")
            }
        }
        val d = Date()
        for (c in certs) {
            c.checkValidity(d)
        }
        zip.entries().iterator().forEach {
            if (it.name.startsWith("NSM/")) return@forEach
            if (it.isDirectory) return@forEach

            val sg = zip.getEntry("NSM/sig/" + it.name)
            if (sg == null) {
                warning("Signature of ${it.name} not found.")
                return@forEach
            }
            val data = zip.getInputStream(sg).use { s -> s.readBytes() }

            val str = zip.getInputStream(it)!!
            val signature: Signature = Signature.getInstance(last.sigAlgName)
            signature.initVerify(last.publicKey)
            str.use { input ->
                val buffer = ByteArray(1024)
                while (true) {
                    val length = input.read(buffer)
                    if (length == -1) break
                    signature.update(buffer, 0, length)
                }
            }
            if (!signature.verify(data)) throw SecurityException("Sign ${it.name} invalid")
        }
        return true
    }
}
