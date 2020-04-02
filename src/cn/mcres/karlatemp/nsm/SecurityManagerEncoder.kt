/*
 * Copyright (c) 2018-2020 Karlatemp. All rights reserved.
 * @author Karlatemp <karlatemp@vip.qq.com> <https://github.com/Karlatemp>
 * @create 2020/04/02 19:59:27
 *
 * NetworkSecurityManager/NetworkSecurityManager/SecurityManagerEncoder.kt
 */

package cn.mcres.karlatemp.nsm

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

object SecurityManagerEncoder {
    @Throws(IOException::class, NoSuchAlgorithmException::class, SignatureException::class)
    fun encode(
        zip: ZipFile,
        output: OutputStream,
        cert: X509Certificate,
        privateKey: PrivateKey,
        parents: Collection<X509Certificate>
    ) {
        ZipOutputStream(output).use { zipOut ->
            zip.entries().iterator().forEach { entry ->
                if (entry.isDirectory) {
                    zipOut.putNextEntry(entry)
                    return@forEach
                }
                val copied = ZipEntry(entry.name)
                if (entry.lastAccessTime != null) copied.lastAccessTime = entry.lastAccessTime
                if (entry.lastModifiedTime != null) copied.lastModifiedTime = entry.lastModifiedTime
                zipOut.putNextEntry(copied)
                val bytes = zip.getInputStream(entry).readBytes()
                zipOut.write(bytes)
                val sign = ZipEntry("NSM/sig/${entry.name}")
                zipOut.putNextEntry(sign)
                val signature: Signature = Signature.getInstance(cert.sigAlgName)
                signature.initSign(privateKey)
                signature.update(bytes)
                zipOut.write(signature.sign())
            }
            val names = LinkedList<String>() as MutableList<String>
            val linked =  LinkedList<X509Certificate>(parents) as MutableList<X509Certificate>
            linked.add(cert)
            for (c in linked) {
                val n = UUID.randomUUID().toString()
                val ent = ZipEntry("NSM/cert/${n}.cert")
                zipOut.putNextEntry(ent)
                zipOut.write(c.encoded)
                names.add(n)
            }
            val x509 = ZipEntry("NSM/x509")
            zipOut.putNextEntry(x509)
            for (name in names) {
                @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
                zipOut.write((name as java.lang.String).getBytes(StandardCharsets.UTF_8))
                zipOut.write('\n'.toInt())
            }
        }
    }
}