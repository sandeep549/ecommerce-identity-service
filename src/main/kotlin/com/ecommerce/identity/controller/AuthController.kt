package com.ecommerce.identity.controller

import com.ecommerce.identity.dto.AuthResponse
import com.ecommerce.identity.dto.LoginRequest
import com.ecommerce.identity.dto.SignupPendingResponse
import com.ecommerce.identity.dto.SignupRequest
import com.ecommerce.identity.dto.SignupResult
import com.ecommerce.identity.service.SupabaseAuthService
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/auth")
class AuthController(private val supabaseAuthService: SupabaseAuthService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    @PostMapping("/signup")
    fun signup(@RequestBody request: SignupRequest): ResponseEntity<*> {
        logger.info("POST /auth/signup - email={}", request.email)
        return when (val result = supabaseAuthService.signup(request)) {
            is SignupResult.Success -> {
                logger.info("Signup successful for email={}", request.email)
                ResponseEntity.status(HttpStatus.CREATED).body(result.authResponse)
            }
            is SignupResult.PendingConfirmation -> {
                logger.info("Signup pending email confirmation for email={}", request.email)
                ResponseEntity.status(HttpStatus.ACCEPTED).body(
                    SignupPendingResponse(
                        message = "Account created. Please check your email to confirm before logging in.",
                        email = result.email
                    )
                )
            }
        }
    }

    @PostMapping("/login")
    fun login(@RequestBody request: LoginRequest): ResponseEntity<AuthResponse> {
        logger.info("POST /auth/login - email={}", request.email)
        val response = supabaseAuthService.login(request)
        logger.info("Login successful for email={}", request.email)
        return ResponseEntity.ok(response)
    }
}
