package com.ecommerce.common.dto

data class ProductDTO(
    val id: Long? = null,
    val name: String,
    val description: String?,
    val price: Double,
    val category: String?,
    val imageUrl: String? = null
)

data class StockDTO(
    val productId: Long,
    val quantity: Int
)

data class OrderItemDTO(
    val productId: Long,
    val quantity: Int,
    val unitPrice: Double? = null
)

data class OrderDTO(
    val id: Long? = null,
    val userId: String,
    val items: List<OrderItemDTO>,
    val status: String? = "PENDING",
    val totalAmount: Double? = null
)

data class ErrorResponse(
    val status: Int,
    val error: String,
    val message: String,
    val path: String? = null
)
