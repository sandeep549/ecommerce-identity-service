package com.ecommerce.common.config

import org.slf4j.LoggerFactory
import org.springframework.boot.SpringApplication
import org.springframework.boot.env.EnvironmentPostProcessor
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.MapPropertySource
import java.net.URI

/**
 * Converts Neon/PostgreSQL URI format to JDBC format before Spring datasource beans are created.
 * Neon provides: postgresql://user:pass@host/db?sslmode=require
 * Spring needs:  jdbc:postgresql://host/db?user=user&password=pass&sslmode=require
 */
class NeonUrlPostProcessor : EnvironmentPostProcessor {

    private val logger = LoggerFactory.getLogger(javaClass)

    override fun postProcessEnvironment(environment: ConfigurableEnvironment, application: SpringApplication) {
        val key = "spring.datasource.url"
        val raw = environment.getProperty(key) ?: return

        val jdbcUrl = toJdbcUrl(raw) ?: return

        if (jdbcUrl == raw) return

        logger.info("NeonUrlPostProcessor: converting datasource URL from postgresql:// to jdbc:postgresql://")
        environment.propertySources.addFirst(
            MapPropertySource("neonUrlNormalizer", mapOf(key to jdbcUrl))
        )
    }

    private fun toJdbcUrl(url: String): String? {
        val normalized = when {
            url.startsWith("postgresql://") -> url.replaceFirst("postgresql://", "postgres://")
            url.startsWith("postgres://") -> url
            else -> return null
        }

        return try {
            val uri = URI(normalized)
            val host = uri.host
            val port = if (uri.port != -1) ":${uri.port}" else ""
            val db = uri.path.trimStart('/')
            val userInfo = uri.userInfo?.split(":", limit = 2)
            val user = userInfo?.getOrNull(0)
            val password = userInfo?.getOrNull(1)

            val existingParams = uri.query
                ?.split("&")
                ?.filter { it.isNotEmpty() && !it.startsWith("channel_binding=") }
                ?: emptyList()

            val params = buildList {
                if (user != null) add("user=$user")
                if (password != null) add("password=$password")
                addAll(existingParams)
            }

            val queryString = if (params.isNotEmpty()) "?${params.joinToString("&")}" else ""
            "jdbc:postgresql://$host$port/$db$queryString"
        } catch (e: Exception) {
            logger.warn("NeonUrlPostProcessor: failed to parse URL, leaving as-is. Error: {}", e.message)
            null
        }
    }
}
