package com.ecommerce.common.exception

import com.ecommerce.common.dto.ErrorResponse
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

class ResourceNotFoundException(message: String) : RuntimeException(message)
class BadRequestException(message: String) : RuntimeException(message)
class InsufficientStockException(message: String) : RuntimeException(message)

@RestControllerAdvice
class GlobalExceptionHandler {

    private val logger = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(ResourceNotFoundException::class)
    fun handleNotFound(ex: ResourceNotFoundException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        logger.warn("Resource not found - path={}, message={}", request.requestURI, ex.message)
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            ErrorResponse(404, "Not Found", ex.message ?: "Resource not found", request.requestURI)
        )
    }

    @ExceptionHandler(BadRequestException::class)
    fun handleBadRequest(ex: BadRequestException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        logger.warn("Bad request - path={}, message={}", request.requestURI, ex.message)
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse(400, "Bad Request", ex.message ?: "Invalid request", request.requestURI)
        )
    }

    @ExceptionHandler(InsufficientStockException::class)
    fun handleInsufficientStock(ex: InsufficientStockException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        logger.warn("Insufficient stock - path={}, message={}", request.requestURI, ex.message)
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
            ErrorResponse(409, "Conflict", ex.message ?: "Insufficient stock", request.requestURI)
        )
    }

    @ExceptionHandler(Exception::class)
    fun handleGeneric(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        logger.error("Unhandled exception - path={}, message={}", request.requestURI, ex.message, ex)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
            ErrorResponse(500, "Internal Server Error", ex.message ?: "Unexpected error", request.requestURI)
        )
    }
}
