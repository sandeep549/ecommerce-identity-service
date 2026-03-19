package com.ecommerce.identity.service

import com.ecommerce.identity.dto.AuthResponse
import com.ecommerce.identity.dto.LoginRequest
import com.ecommerce.identity.dto.SignupRequest
import com.ecommerce.identity.dto.SignupResult
import com.ecommerce.identity.dto.UserInfo
import io.netty.channel.ChannelOption
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientRequestException
import org.springframework.web.reactive.function.client.WebClientResponseException
import org.springframework.web.reactive.function.client.bodyToMono
import reactor.netty.http.client.HttpClient
import reactor.netty.resources.ConnectionProvider
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import java.time.Duration

@Service
class SupabaseAuthService(
    @Value("\${supabase.url}") private val supabaseUrl: String,
    @Value("\${supabase.anon-key}") private val supabaseAnonKey: String
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private val webClient: WebClient = run {
        // Evict idle connections before Supabase closes them server-side.
        // Default Netty pool has no idle timeout, causing "Connection reset by peer" on reuse.
        val connectionProvider = ConnectionProvider.builder("supabase")
            .maxConnections(10)
            .maxIdleTime(Duration.ofSeconds(15))
            .maxLifeTime(Duration.ofSeconds(60))
            .evictInBackground(Duration.ofSeconds(20))
            .build()

        val httpClient = HttpClient.create(connectionProvider)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
            .responseTimeout(Duration.ofSeconds(30))

        WebClient.builder()
            .baseUrl("$supabaseUrl/auth/v1")
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .defaultHeader("apikey", supabaseAnonKey)
            .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
            .build()
    }

    fun signup(request: SignupRequest): SignupResult {
        logger.info("Calling Supabase /auth/v1/signup for email={}", request.email)
        val body = mapOf("email" to request.email, "password" to request.password)
        val response = callSupabase("/signup", body)
        logger.debug("Supabase signup response keys={}", response.keys)
        return parseSignupResponse(response, request.email)
    }

    fun login(request: LoginRequest): AuthResponse {
        logger.info("Calling Supabase /auth/v1/token for email={}", request.email)
        val body = mapOf("email" to request.email, "password" to request.password)
        val response = callSupabase("/token?grant_type=password", body)
        logger.debug("Supabase login response keys={}", response.keys)
        return parseAuthResponse(response)
    }

    private fun callSupabase(uri: String, body: Map<String, String>): Map<String, Any> {
        return try {
            webClient.post()
                .uri(uri)
                .bodyValue(body)
                .retrieve()
                .bodyToMono<Map<String, Any>>()
                .retry(1) // retry once if connection was stale/reset
                .block() ?: throw RuntimeException("Empty response from Supabase")
        } catch (e: WebClientResponseException) {
            // HTTP error from Supabase (e.g. 429 Too Many Requests, 422 Unprocessable Entity)
            logger.warn("Supabase returned HTTP {} for uri={}: {}", e.statusCode.value(), uri, e.responseBodyAsString)
            throw RuntimeException("Supabase error ${e.statusCode.value()}: ${e.responseBodyAsString}")
        } catch (e: WebClientRequestException) {
            // Network/connection error (e.g. connection reset, timeout)
            logger.error("Network error calling Supabase uri={}: {}", uri, e.message)
            throw RuntimeException("Could not reach authentication service. Please try again.")
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseSignupResponse(response: Map<String, Any>, email: String): SignupResult {
        val accessToken = response["access_token"] as? String
        if (accessToken != null) {
            // Email confirmation is off — token returned immediately
            return SignupResult.Success(parseAuthTokenFromResponse(response))
        }
        // When Supabase requires email confirmation, it returns a user object with confirmation_sent_at but no access_token
        if (response.containsKey("confirmation_sent_at") || response.containsKey("id")) {
            logger.info("Signup pending email confirmation for email={}", email)
            return SignupResult.PendingConfirmation(email)
        }
        val errorDesc = response["error_description"] ?: response["msg"] ?: response["error"] ?: "Unknown error"
        logger.warn("Supabase signup failed. Response keys={}, error={}", response.keys, errorDesc)
        throw RuntimeException("Auth failed: $errorDesc")
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseAuthTokenFromResponse(response: Map<String, Any>): AuthResponse {
        val accessToken = response["access_token"] as String
        val expiresIn = (response["expires_in"] as? Number)?.toLong()
        val userMap = response["user"] as? Map<String, Any>
        val user = userMap?.let {
            UserInfo(id = it["id"] as? String ?: "", email = it["email"] as? String ?: "")
        }
        logger.info("Auth token issued for userId={}", user?.id)
        return AuthResponse(accessToken = accessToken, expiresIn = expiresIn, user = user)
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseAuthResponse(response: Map<String, Any>): AuthResponse {
        val accessToken = response["access_token"] as? String
        if (accessToken == null) {
            val errorDesc = response["error_description"] ?: response["msg"] ?: response["error"] ?: "Unknown error"
            logger.warn("Supabase did not return access_token. Response keys={}, error={}", response.keys, errorDesc)
            throw RuntimeException("Auth failed: $errorDesc")
        }
        return parseAuthTokenFromResponse(response)
    }
}
