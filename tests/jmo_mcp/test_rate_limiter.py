"""
Tests for MCP server rate limiting (token bucket algorithm).

Tests:
- TokenBucket basic functionality
- TokenBucket thread safety
- TokenBucket refill behavior
- RateLimiter per-client tracking
- RateLimiter reset functionality
"""

import time
import threading
import pytest

from scripts.jmo_mcp.utils.rate_limiter import TokenBucket, RateLimiter


class TestTokenBucket:
    """Test TokenBucket class (single client bucket)."""

    def test_initial_capacity(self):
        """Test bucket starts at full capacity."""
        bucket = TokenBucket(capacity=100, refill_rate=1.0)
        assert bucket.get_remaining_tokens() == 100.0

    def test_consume_tokens(self):
        """Test consuming tokens reduces count."""
        bucket = TokenBucket(capacity=100, refill_rate=1.0)

        # Consume 10 tokens
        assert bucket.consume(10) is True
        assert 89.0 < bucket.get_remaining_tokens() < 91.0  # ~90 (allow for time drift)

    def test_consume_all_tokens(self):
        """Test consuming all tokens."""
        bucket = TokenBucket(capacity=100, refill_rate=1.0)

        # Consume all tokens
        assert bucket.consume(100) is True
        assert bucket.get_remaining_tokens() < 1.0  # Nearly empty

    def test_consume_too_many_tokens(self):
        """Test consuming more tokens than available fails."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)

        # Consume 8 tokens
        assert bucket.consume(8) is True

        # Try to consume 5 more (only ~2 left)
        assert bucket.consume(5) is False

        # Remaining should still be ~2
        assert 1.0 < bucket.get_remaining_tokens() < 3.0

    def test_refill_over_time(self):
        """Test tokens refill over time."""
        bucket = TokenBucket(capacity=100, refill_rate=10.0)  # 10 tokens/sec

        # Consume 50 tokens
        bucket.consume(50)
        assert 45.0 < bucket.get_remaining_tokens() < 55.0  # ~50 left

        # Wait 1 second (should add ~10 tokens)
        time.sleep(1.0)

        # Should have ~60 tokens now
        remaining = bucket.get_remaining_tokens()
        assert 55.0 < remaining < 65.0

    def test_refill_capped_at_capacity(self):
        """Test refill does not exceed capacity."""
        bucket = TokenBucket(capacity=100, refill_rate=50.0)  # 50 tokens/sec

        # Start with full capacity
        assert bucket.get_remaining_tokens() == 100.0

        # Wait 2 seconds (would add 100 tokens if not capped)
        time.sleep(2.0)

        # Should still be capped at 100
        remaining = bucket.get_remaining_tokens()
        assert 95.0 < remaining <= 100.0

    def test_thread_safety(self):
        """Test concurrent consume() calls are thread-safe."""
        bucket = TokenBucket(capacity=1000, refill_rate=0.0)  # No refill
        results = []

        def consume_batch():
            """Consume 10 tokens in a thread."""
            result = bucket.consume(10)
            results.append(result)

        # Launch 110 threads (1100 tokens requested, 1000 available)
        threads = [threading.Thread(target=consume_batch) for _ in range(110)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Expect 100 successes, 10 failures
        successes = sum(results)
        failures = len(results) - successes

        assert successes == 100  # 100 * 10 = 1000 tokens consumed
        assert failures == 10  # 10 threads failed

    def test_zero_refill_rate(self):
        """Test bucket with zero refill rate (fixed capacity)."""
        bucket = TokenBucket(capacity=10, refill_rate=0.0)

        # Consume all tokens
        assert bucket.consume(10) is True
        assert bucket.get_remaining_tokens() < 1.0

        # Wait 1 second (no refill)
        time.sleep(1.0)

        # Still empty
        assert bucket.get_remaining_tokens() < 1.0


class TestRateLimiter:
    """Test RateLimiter class (multi-client tracker)."""

    def test_initial_state(self):
        """Test rate limiter starts with no clients tracked."""
        limiter = RateLimiter(capacity=100, refill_rate=1.0)

        # No clients tracked yet
        assert len(limiter.buckets) == 0

    def test_single_client_tracking(self):
        """Test rate limiter tracks single client."""
        limiter = RateLimiter(capacity=10, refill_rate=1.0)

        # Client makes 5 requests
        for _ in range(5):
            assert limiter.check_rate_limit("client1") is True

        # Client tracked
        assert "client1" in limiter.buckets

        # Client has ~5 tokens left
        status = limiter.get_client_status("client1")
        assert 4.0 < status["remaining_tokens"] < 6.0

    def test_multiple_clients_independent(self):
        """Test rate limiter tracks multiple clients independently."""
        limiter = RateLimiter(capacity=10, refill_rate=0.0)

        # Client 1 makes 10 requests (consumes all)
        for _ in range(10):
            assert limiter.check_rate_limit("client1") is True

        # Client 1 exhausted
        assert limiter.check_rate_limit("client1") is False

        # Client 2 still has full capacity
        assert limiter.check_rate_limit("client2") is True
        status = limiter.get_client_status("client2")
        assert 8.0 < status["remaining_tokens"] < 10.0

    def test_rate_limit_exceeded(self):
        """Test rate limit returns False when exceeded."""
        limiter = RateLimiter(capacity=5, refill_rate=0.0)

        # Make 5 requests (all succeed)
        for _ in range(5):
            assert limiter.check_rate_limit("client1") is True

        # 6th request fails
        assert limiter.check_rate_limit("client1") is False

    def test_get_client_status(self):
        """Test get_client_status returns correct info."""
        limiter = RateLimiter(capacity=100, refill_rate=1.67)

        # Client makes 20 requests
        for _ in range(20):
            limiter.check_rate_limit("client1")

        # Check status
        status = limiter.get_client_status("client1")
        assert 75.0 < status["remaining_tokens"] < 85.0  # ~80 left
        assert status["capacity"] == 100
        assert status["refill_rate"] == 1.67

    def test_reset_client(self):
        """Test reset_client restores full capacity."""
        limiter = RateLimiter(capacity=10, refill_rate=0.0)

        # Exhaust client's tokens
        for _ in range(10):
            limiter.check_rate_limit("client1")

        # Client exhausted
        assert limiter.check_rate_limit("client1") is False

        # Reset client
        limiter.reset_client("client1")

        # Client has full capacity again
        assert limiter.check_rate_limit("client1") is True
        status = limiter.get_client_status("client1")
        assert 8.0 < status["remaining_tokens"] < 10.0

    def test_reset_all(self):
        """Test reset_all clears all client buckets."""
        limiter = RateLimiter(capacity=10, refill_rate=0.0)

        # Multiple clients make requests
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client2")
        limiter.check_rate_limit("client3")

        # Verify tracked
        assert len(limiter.buckets) == 3

        # Reset all
        limiter.reset_all()

        # All buckets cleared
        assert len(limiter.buckets) == 0

    def test_default_configuration(self):
        """Test default rate limit configuration (100 req/min)."""
        limiter = RateLimiter()  # Defaults: capacity=100, refill_rate=1.67

        # Should allow 100 burst requests
        for _ in range(100):
            assert limiter.check_rate_limit("client1") is True

        # 101st request fails
        assert limiter.check_rate_limit("client1") is False

    def test_sustained_rate_limiting(self):
        """Test sustained rate limiting with refill."""
        limiter = RateLimiter(capacity=10, refill_rate=5.0)  # 5 tokens/sec

        # Consume 8 tokens
        for _ in range(8):
            assert limiter.check_rate_limit("client1") is True

        # Wait 1 second (refill ~5 tokens)
        time.sleep(1.0)

        # Should have ~7 tokens now (2 remaining + 5 refilled)
        for _ in range(7):
            assert limiter.check_rate_limit("client1") is True

        # Next request fails
        assert limiter.check_rate_limit("client1") is False


class TestRateLimiterEdgeCases:
    """Test edge cases and error scenarios."""

    def test_zero_capacity(self):
        """Test zero capacity bucket (always rejects)."""
        bucket = TokenBucket(capacity=0, refill_rate=1.0)

        # Cannot consume any tokens
        assert bucket.consume(1) is False
        assert bucket.get_remaining_tokens() == 0.0

    def test_fractional_tokens(self):
        """Test consuming fractional tokens."""
        bucket = TokenBucket(capacity=10.5, refill_rate=1.0)

        # Consume 0.5 tokens
        assert bucket.consume(0.5) is True

        # Should have ~10.0 left
        remaining = bucket.get_remaining_tokens()
        assert 9.5 < remaining < 10.5

    def test_high_concurrency(self):
        """Test rate limiter under high concurrent load."""
        limiter = RateLimiter(capacity=1000, refill_rate=0.0)
        results = []

        def make_request(client_id: str):
            """Make single request."""
            result = limiter.check_rate_limit(client_id)
            results.append((client_id, result))

        # 100 clients, 15 requests each (1500 total, 1000 capacity)
        threads = []
        for client_id in range(100):
            for _ in range(15):
                t = threading.Thread(target=make_request, args=(f"client{client_id}",))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        # Count successes per client (each should get ~10 tokens)
        successes_per_client = {}
        for client_id, success in results:
            if client_id not in successes_per_client:
                successes_per_client[client_id] = 0
            if success:
                successes_per_client[client_id] += 1

        # Each client should have gotten some tokens (not exact due to concurrency)
        for client_id, count in successes_per_client.items():
            assert count > 0  # At least some requests succeeded
            assert count <= 15  # Not more than requested
