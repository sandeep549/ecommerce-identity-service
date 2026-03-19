package com.ecommerce.identity.dto

data class SignupRequest(
    val email: String,
    val password: String
)

data class LoginRequest(
    val email: String,
    val password: String
)

data class AuthResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long? = null,
    val user: UserInfo? = null
)

data class UserInfo(
    val id: String,
    val email: String
)

data class SignupPendingResponse(
    val message: String,
    val email: String
)

sealed class SignupResult {
    data class Success(val authResponse: AuthResponse) : SignupResult()
    data class PendingConfirmation(val email: String) : SignupResult()
}
