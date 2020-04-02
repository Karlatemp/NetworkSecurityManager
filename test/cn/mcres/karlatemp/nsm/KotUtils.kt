/*
 * Copyright (c) 2018-2020 Karlatemp. All rights reserved.
 * @author Karlatemp <karlatemp@vip.qq.com> <https://github.com/Karlatemp>
 * @create 2020/04/02 20:30:26
 *
 * NetworkSecurityManager/NetworkSecurityManager/KotUtils.kt
 */

package cn.mcres.karlatemp.nsm

import java.io.FileInputStream

/**
 * Create at 2020/4/2 20:30
 * Copyright Karlatemp
 * NetworkSecurityManager $ cn.mcres.karlatemp.nsm
 */
object KotUtils {
    fun read(file: String): ByteArray = FileInputStream(file).readBytes()
}