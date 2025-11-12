"""Simple benchmark harness for PQ-FSR reference implementation."""

import argparse
import time

from pqfsr import RatchetSession


def run_benchmark(message_count: int, message_size: int) -> None:
    alice = RatchetSession.create_initiator(semantic_hint=b"alice")
    bob = RatchetSession.create_responder(semantic_hint=b"bob")

    req = alice.create_handshake_request()
    resp = bob.accept_handshake(req)
    alice.finalize_handshake(resp)

    payload = b"Q" * message_size

    start = time.perf_counter()
    packets = [alice.encrypt(payload) for _ in range(message_count)]
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    for packet in packets:
        bob.decrypt(packet)
    dec_time = time.perf_counter() - start

    print(f"Messages: {message_count}")
    print(f"Size: {message_size} bytes")
    print(f"Encrypt total: {enc_time:.6f}s ({enc_time / message_count:.6e}s per msg)")
    print(f"Decrypt total: {dec_time:.6f}s ({dec_time / message_count:.6e}s per msg)")


def main():
    parser = argparse.ArgumentParser(description="Benchmark PQ-FSR reference implementation")
    parser.add_argument("--messages", type=int, default=100, help="Number of messages to send")
    parser.add_argument("--size", type=int, default=256, help="Message size in bytes")
    args = parser.parse_args()
    run_benchmark(args.messages, args.size)


if __name__ == "__main__":
    main()
