"""
Rate limiting for MCP server using token bucket algorithm.

Provides per-client rate limiting to prevent abuse while allowing
burst traffic. Configurable capacity and refill rate.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import DefaultDict


class TokenBucket:
    """
    Token bucket rate limiter.

    Allows burst traffic up to capacity, then enforces sustained rate.
    Thread-safe for concurrent requests.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum tokens (burst size). Example: 100 for burst of 100 requests.
            refill_rate: Tokens added per second. Example: 1.67 for 100 req/min sustained.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate

        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens.

        Args:
            tokens: Number of tokens to consume (default: 1 for single request).

        Returns:
            True if tokens available and consumed, False if rate limit exceeded.
        """
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_remaining_tokens(self) -> float:
        """
        Get remaining tokens without consuming.

        Returns:
            Number of tokens currently available.
        """
        with self.lock:
            self._refill()
            return self.tokens


class RateLimiter:
    """
    Per-client rate limiter using token bucket algorithm.

    Tracks separate buckets for each client (identified by API key or IP).
    Thread-safe for concurrent requests.
    """

    def __init__(self, capacity: int = 100, refill_rate: float = 1.67):
        """
        Initialize rate limiter with default limits.

        Args:
            capacity: Burst size (default: 100 requests).
            refill_rate: Sustained rate in tokens/sec (default: 1.67 = 100 req/min).
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets: DefaultDict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.capacity, self.refill_rate)
        )
        self.lock = Lock()

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if client can make a request.

        Args:
            client_id: Identifier for client (API key hash or IP address).

        Returns:
            True if request allowed, False if rate limit exceeded.
        """
        with self.lock:
            bucket = self.buckets[client_id]

        return bucket.consume(tokens=1)

    def get_client_status(self, client_id: str) -> dict[str, float]:
        """
        Get rate limit status for client.

        Args:
            client_id: Identifier for client.

        Returns:
            Dict with 'remaining_tokens', 'capacity', 'refill_rate'.
        """
        with self.lock:
            bucket = self.buckets[client_id]

        return {
            "remaining_tokens": bucket.get_remaining_tokens(),
            "capacity": bucket.capacity,
            "refill_rate": bucket.refill_rate,
        }

    def reset_client(self, client_id: str) -> None:
        """
        Reset rate limit for specific client.

        Args:
            client_id: Identifier for client to reset.
        """
        with self.lock:
            if client_id in self.buckets:
                del self.buckets[client_id]

    def reset_all(self) -> None:
        """Reset rate limits for all clients."""
        with self.lock:
            self.buckets.clear()
