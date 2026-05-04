#!/usr/bin/env python3
"""
Benchmark script for tiny_ca performance testing.

Measures execution time for all major operations (sync + async)
and generates a markdown table for README.

Run with: python benchmark.py
"""

import asyncio
import time
import platform
import psutil
import sys
from pathlib import Path
from datetime import datetime, UTC
from statistics import mean, stdev
from typing import Dict, List, Tuple, Any
import tempfile
import shutil

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.storage.local_storage import LocalStorage
from tiny_ca.storage.async_local_storage import AsyncLocalStorage
from tiny_ca.db.sync_db_manager import SyncDBHandler
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.models.certificate import CAConfig, ClientConfig
from tiny_ca.const import CertType
from tiny_ca.ca_factory.utils.file_loader import CAFileLoader
from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
from tiny_ca.ca_factory.factory import CertificateFactory


def get_system_info() -> Dict[str, str]:
    """Collect system information for benchmark context."""
    return {
        "Platform": platform.platform(),
        "Python": platform.python_version(),
        "CPU": platform.processor() or "Unknown",
        "CPU Cores": str(psutil.cpu_count(logical=True)),
        "RAM": f"{psutil.virtual_memory().total // (1024**3)} GB",
        "Disk": "NVMe SSD" if "nvme" in str(psutil.disk_partitions()) else "SSD/HDD",
    }


class Benchmark:
    """Run benchmarks for sync and async operations."""

    def __init__(self, iterations: int = 5):
        self.iterations = iterations
        self.results: Dict[str, List[float]] = {}
        self.temp_dir = Path(tempfile.mkdtemp(prefix="tiny_ca_benchmark_"))

    def cleanup(self):
        """Clean up temporary directory."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _sync_setup(
        self,
    ) -> Tuple[CertLifecycleManager, CertificateFactory, Path, Path]:
        """Setup sync infrastructure."""
        storage = LocalStorage(base_folder=str(self.temp_dir / "pki"))
        db = SyncDBHandler(db_url="sqlite:///pki.db")

        mgr = CertLifecycleManager(storage=storage, db_handler=db)

        config = CAConfig(
            common_name="Benchmark CA",
            organization="Benchmark",
            country="UA",
            key_size=2048,
            days_valid=365,
        )
        cert_path, key_path = mgr.create_self_signed_ca(config, is_overwrite=True)

        loader = CAFileLoader(ca_cert_path=cert_path, ca_key_path=key_path)
        factory = CertificateFactory(loader)
        mgr.factory = factory

        return mgr, factory, cert_path, key_path

    async def _async_setup(
        self,
    ) -> Tuple[AsyncCertLifecycleManager, CertificateFactory, Path, Path]:
        """Setup async infrastructure."""
        storage = AsyncLocalStorage(base_folder=str(self.temp_dir / "pki_async"))
        db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki_async.db")
        await db._db.init_db()

        mgr = AsyncCertLifecycleManager(storage=storage, db_handler=db)

        config = CAConfig(
            common_name="Benchmark Async CA",
            organization="Benchmark",
            country="UA",
            key_size=2048,
            days_valid=365,
        )
        cert_path, key_path = await mgr.create_self_signed_ca(config, is_overwrite=True)

        loader = await AsyncCAFileLoader.create(cert_path, key_path)
        factory = CertificateFactory(loader)
        mgr.factory = factory

        return mgr, factory, cert_path, key_path

    def benchmark_sync_ca_creation(self, iterations: int = 5) -> float:
        """Benchmark CA creation (2048-bit)."""
        times = []
        for i in range(iterations):
            storage = LocalStorage(base_folder=str(self.temp_dir / f"pki_ca_{i}"))
            db = SyncDBHandler(db_url="sqlite:///pki_ca.db")
            mgr = CertLifecycleManager(storage=storage, db_handler=db)

            config = CAConfig(
                common_name=f"CA_{i}",
                organization="Benchmark",
                country="UA",
                key_size=2048,
                days_valid=365,
            )

            start = time.perf_counter()
            cert_path, key_path = mgr.create_self_signed_ca(config, is_overwrite=True)
            times.append(time.perf_counter() - start)

        return mean(times)

    def benchmark_sync_ca_creation_4096(self, iterations: int = 5) -> float:
        """Benchmark CA creation (4096-bit)."""
        times = []
        for i in range(iterations):
            storage = LocalStorage(base_folder=str(self.temp_dir / f"pki_ca_4096_{i}"))
            db = SyncDBHandler(db_url="sqlite:///pki_ca_4096.db")
            mgr = CertLifecycleManager(storage=storage, db_handler=db)

            config = CAConfig(
                common_name=f"CA_4096_{i}",
                organization="Benchmark",
                country="UA",
                key_size=4096,
                days_valid=365,
            )

            start = time.perf_counter()
            cert_path, key_path = mgr.create_self_signed_ca(config, is_overwrite=True)
            times.append(time.perf_counter() - start)

        return mean(times)

    def benchmark_sync_leaf_issuance(self, iterations: int = 10) -> Tuple[float, float]:
        """Benchmark leaf certificate issuance (2048-bit and 4096-bit)."""
        mgr, factory, _, _ = self._sync_setup()

        times_2048 = []
        times_4096 = []

        for i in range(iterations):
            config_2048 = ClientConfig(
                common_name=f"leaf_{i}.test",
                serial_type=CertType.SERVICE,
                key_size=2048,
                days_valid=365,
                is_server_cert=True,
            )
            start = time.perf_counter()
            cert, key, csr = mgr.issue_certificate(config_2048, is_overwrite=True)
            times_2048.append(time.perf_counter() - start)

        for i in range(iterations):
            config_4096 = ClientConfig(
                common_name=f"leaf_4096_{i}.test",
                serial_type=CertType.SERVICE,
                key_size=4096,
                days_valid=365,
                is_server_cert=True,
            )
            start = time.perf_counter()
            cert, key, csr = mgr.issue_certificate(config_4096, is_overwrite=True)
            times_4096.append(time.perf_counter() - start)

        return mean(times_2048), mean(times_4096)

    def benchmark_sync_crl_generation(self, iterations: int = 10) -> float:
        """Benchmark CRL generation."""
        mgr, factory, _, _ = self._sync_setup()

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            crl = mgr.generate_crl(days_valid=7)
            times.append(time.perf_counter() - start)

        return mean(times)

    def benchmark_sync_verification(self, iterations: int = 50) -> float:
        """Benchmark certificate verification."""
        mgr, factory, _, _ = self._sync_setup()

        config = ClientConfig(
            common_name="verify.test",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
        )
        cert, key, csr = mgr.issue_certificate(config, is_overwrite=True)

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            mgr.verify_certificate(cert)
            times.append(time.perf_counter() - start)

        return mean(times)

    def benchmark_sync_pkcs12_export(self, iterations: int = 50) -> float:
        """Benchmark PKCS#12 export."""
        mgr, factory, _, _ = self._sync_setup()

        config = ClientConfig(
            common_name="pkcs12.test",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
        )
        cert, key, csr = mgr.issue_certificate(config, is_overwrite=True)

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            p12_bytes = mgr.export_pkcs12(cert, key)
            times.append(time.perf_counter() - start)

        return mean(times)

    async def benchmark_async_ca_creation(self, iterations: int = 5) -> float:
        """Benchmark async CA creation (2048-bit)."""
        times = []
        for i in range(iterations):
            storage = AsyncLocalStorage(
                base_folder=str(self.temp_dir / f"pki_async_ca_{i}")
            )
            db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki_async_ca.db")
            await db._db.init_db()
            mgr = AsyncCertLifecycleManager(storage=storage, db_handler=db)

            config = CAConfig(
                common_name=f"Async_CA_{i}",
                organization="Benchmark",
                country="UA",
                key_size=2048,
                days_valid=365,
            )

            start = time.perf_counter()
            cert_path, key_path = await mgr.create_self_signed_ca(
                config, is_overwrite=True
            )
            times.append(time.perf_counter() - start)

        return mean(times)

    async def benchmark_async_ca_creation_4096(self, iterations: int = 5) -> float:
        """Benchmark async CA creation (4096-bit)."""
        times = []
        for i in range(iterations):
            storage = AsyncLocalStorage(
                base_folder=str(self.temp_dir / f"pki_async_ca_4096_{i}")
            )
            db = AsyncDBHandler(db_url="sqlite+aiosqlite:///pki_async_ca_4096.db")
            await db._db.init_db()
            mgr = AsyncCertLifecycleManager(storage=storage, db_handler=db)

            config = CAConfig(
                common_name=f"Async_CA_4096_{i}",
                organization="Benchmark",
                country="UA",
                key_size=4096,
                days_valid=365,
            )

            start = time.perf_counter()
            cert_path, key_path = await mgr.create_self_signed_ca(
                config, is_overwrite=True
            )
            times.append(time.perf_counter() - start)

        return mean(times)

    async def benchmark_async_leaf_issuance(
        self, iterations: int = 10
    ) -> Tuple[float, float]:
        """Benchmark async leaf certificate issuance."""
        mgr, factory, _, _ = await self._async_setup()

        times_2048 = []
        times_4096 = []

        for i in range(iterations):
            config_2048 = ClientConfig(
                common_name=f"async_leaf_{i}.test",
                serial_type=CertType.SERVICE,
                key_size=2048,
                days_valid=365,
                is_server_cert=True,
            )
            start = time.perf_counter()
            cert, key, csr = await mgr.issue_certificate(config_2048, is_overwrite=True)
            times_2048.append(time.perf_counter() - start)

        for i in range(iterations):
            config_4096 = ClientConfig(
                common_name=f"async_leaf_4096_{i}.test",
                serial_type=CertType.SERVICE,
                key_size=4096,
                days_valid=365,
                is_server_cert=True,
            )
            start = time.perf_counter()
            cert, key, csr = await mgr.issue_certificate(config_4096, is_overwrite=True)
            times_4096.append(time.perf_counter() - start)

        return mean(times_2048), mean(times_4096)

    async def benchmark_async_crl_generation(self, iterations: int = 10) -> float:
        """Benchmark async CRL generation."""
        mgr, factory, _, _ = await self._async_setup()

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            crl = await mgr.generate_crl(days_valid=7)
            times.append(time.perf_counter() - start)

        return mean(times)

    async def benchmark_async_verification(self, iterations: int = 50) -> float:
        """Benchmark async certificate verification."""
        mgr, factory, _, _ = await self._async_setup()

        config = ClientConfig(
            common_name="async_verify.test",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
        )
        cert, key, csr = await mgr.issue_certificate(config, is_overwrite=True)

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            await mgr.verify_certificate(cert)
            times.append(time.perf_counter() - start)

        return mean(times)

    async def benchmark_async_pkcs12_export(self, iterations: int = 50) -> float:
        """Benchmark async PKCS#12 export."""
        mgr, factory, _, _ = await self._async_setup()

        config = ClientConfig(
            common_name="async_pkcs12.test",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
        )
        cert, key, csr = await mgr.issue_certificate(config, is_overwrite=True)

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            p12_bytes = await mgr.export_pkcs12(cert, key)
            times.append(time.perf_counter() - start)

        return mean(times)

    def run_sync_benchmarks(self):
        """Run all sync benchmarks."""
        print("\n📊 Running Sync Benchmarks...")

        self.results["CA Creation (2048-bit)"] = self.benchmark_sync_ca_creation(
            self.iterations
        )
        print(
            f"  ✓ CA Creation (2048-bit): {self.results['CA Creation (2048-bit)']:.3f}s"
        )

        self.results["CA Creation (4096-bit)"] = self.benchmark_sync_ca_creation_4096(
            self.iterations
        )
        print(
            f"  ✓ CA Creation (4096-bit): {self.results['CA Creation (4096-bit)']:.3f}s"
        )

        leaf_2048, leaf_4096 = self.benchmark_sync_leaf_issuance(self.iterations)
        self.results["Leaf Issuance (2048-bit)"] = leaf_2048
        self.results["Leaf Issuance (4096-bit)"] = leaf_4096
        print(f"  ✓ Leaf Issuance (2048-bit): {leaf_2048:.3f}s")
        print(f"  ✓ Leaf Issuance (4096-bit): {leaf_4096:.3f}s")

        self.results["CRL Generation"] = self.benchmark_sync_crl_generation(
            self.iterations
        )
        print(f"  ✓ CRL Generation: {self.results['CRL Generation']:.3f}s")

        self.results["Certificate Verification"] = self.benchmark_sync_verification(50)
        print(
            f"  ✓ Certificate Verification: {self.results['Certificate Verification']:.3f}s"
        )

        self.results["PKCS#12 Export"] = self.benchmark_sync_pkcs12_export(50)
        print(f"  ✓ PKCS#12 Export: {self.results['PKCS#12 Export']:.3f}s")

    async def run_async_benchmarks(self):
        """Run all async benchmarks."""
        print("\n📊 Running Async Benchmarks...")

        self.results[
            "Async CA Creation (2048-bit)"
        ] = await self.benchmark_async_ca_creation(self.iterations)
        print(
            f"  ✓ Async CA Creation (2048-bit): {self.results['Async CA Creation (2048-bit)']:.3f}s"
        )

        self.results[
            "Async CA Creation (4096-bit)"
        ] = await self.benchmark_async_ca_creation_4096(self.iterations)
        print(
            f"  ✓ Async CA Creation (4096-bit): {self.results['Async CA Creation (4096-bit)']:.3f}s"
        )

        leaf_2048, leaf_4096 = await self.benchmark_async_leaf_issuance(self.iterations)
        self.results["Async Leaf Issuance (2048-bit)"] = leaf_2048
        self.results["Async Leaf Issuance (4096-bit)"] = leaf_4096
        print(f"  ✓ Async Leaf Issuance (2048-bit): {leaf_2048:.3f}s")
        print(f"  ✓ Async Leaf Issuance (4096-bit): {leaf_4096:.3f}s")

        self.results[
            "Async CRL Generation"
        ] = await self.benchmark_async_crl_generation(self.iterations)
        print(f"  ✓ Async CRL Generation: {self.results['Async CRL Generation']:.3f}s")

        self.results[
            "Async Certificate Verification"
        ] = await self.benchmark_async_verification(50)
        print(
            f"  ✓ Async Certificate Verification: {self.results['Async Certificate Verification']:.3f}s"
        )

        self.results["Async PKCS#12 Export"] = await self.benchmark_async_pkcs12_export(
            50
        )
        print(f"  ✓ Async PKCS#12 Export: {self.results['Async PKCS#12 Export']:.3f}s")

    def generate_markdown_table(self) -> str:
        """Generate markdown table from benchmark results."""
        lines = []
        lines.append("## Benchmark Results")
        lines.append("")

        # System info
        sys_info = get_system_info()
        lines.append("### Test Environment")
        lines.append("")
        for key, value in sys_info.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")
        lines.append(f"- **Iterations per test:** {self.iterations}")
        lines.append(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Performance table
        lines.append("### Performance Metrics")
        lines.append("")
        lines.append("| Operation | Sync API | Async API |")
        lines.append("|-----------|----------|-----------|")

        ops = [
            (
                "CA Creation (2048-bit)",
                "CA Creation (2048-bit)",
                "Async CA Creation (2048-bit)",
            ),
            (
                "CA Creation (4096-bit)",
                "CA Creation (4096-bit)",
                "Async CA Creation (4096-bit)",
            ),
            (
                "Leaf Issuance (2048-bit)",
                "Leaf Issuance (2048-bit)",
                "Async Leaf Issuance (2048-bit)",
            ),
            (
                "Leaf Issuance (4096-bit)",
                "Leaf Issuance (4096-bit)",
                "Async Leaf Issuance (4096-bit)",
            ),
            ("CRL Generation", "CRL Generation", "Async CRL Generation"),
            (
                "Certificate Verification",
                "Certificate Verification",
                "Async Certificate Verification",
            ),
            ("PKCS#12 Export", "PKCS#12 Export", "Async PKCS#12 Export"),
        ]

        for display, sync_key, async_key in ops:
            sync_time = self.results.get(sync_key, 0)
            async_time = self.results.get(async_key, 0)
            lines.append(f"| {display} | {sync_time:.4f}s | {async_time:.4f}s |")

        lines.append("")

        # Notes
        lines.append("### Notes")
        lines.append("")
        lines.append("- Times are averages across multiple iterations")
        lines.append("- Key generation dominates issuance time")
        lines.append("- Async API has minimal overhead for I/O-bound operations")
        lines.append(
            "- For high-throughput environments (>1,000 certs/hour), consider:"
        )
        lines.append("  - Using PostgreSQL instead of SQLite")
        lines.append("  - Using async API for concurrent operations")
        lines.append("  - Connection pooling")

        return "\n".join(lines)

    def print_results_table(self):
        """Print results as a table."""
        print("\n" + "=" * 70)
        print(" BENCHMARK RESULTS")
        print("=" * 70)

        sys_info = get_system_info()
        print("\n📋 System Information:")
        for key, value in sys_info.items():
            print(f"   {key}: {value}")

        print(f"\n📊 Performance Results (averages over {self.iterations} iterations):")
        print("-" * 70)
        print(f"{'Operation':<35} {'Sync':<12} {'Async':<12}")
        print("-" * 70)

        ops = [
            (
                "CA Creation (2048-bit)",
                "CA Creation (2048-bit)",
                "Async CA Creation (2048-bit)",
            ),
            (
                "CA Creation (4096-bit)",
                "CA Creation (4096-bit)",
                "Async CA Creation (4096-bit)",
            ),
            (
                "Leaf Issuance (2048-bit)",
                "Leaf Issuance (2048-bit)",
                "Async Leaf Issuance (2048-bit)",
            ),
            (
                "Leaf Issuance (4096-bit)",
                "Leaf Issuance (4096-bit)",
                "Async Leaf Issuance (4096-bit)",
            ),
            ("CRL Generation", "CRL Generation", "Async CRL Generation"),
            (
                "Certificate Verification",
                "Certificate Verification",
                "Async Certificate Verification",
            ),
            ("PKCS#12 Export", "PKCS#12 Export", "Async PKCS#12 Export"),
        ]

        for display, sync_key, async_key in ops:
            sync_time = self.results.get(sync_key, 0)
            async_time = self.results.get(async_key, 0)
            print(f"{display:<35} {sync_time:.3f}s{'':<6} {async_time:.3f}s")

        print("-" * 70)

    def run(self):
        """Run all benchmarks and generate output."""
        print("\n" + "🔬" * 35)
        print("  TINY_CA PERFORMANCE BENCHMARK")
        print("🔬" * 35)

        try:
            self.run_sync_benchmarks()
            asyncio.run(self.run_async_benchmarks())

            self.print_results_table()

            # Generate markdown for README
            markdown = self.generate_markdown_table()

            # Save to file
            output_file = self.temp_dir / "benchmark_results.md"
            output_file.write_text(markdown)
            print(f"\n📄 Markdown table saved to: {output_file}")

            # Also print markdown to console
            print("\n" + "=" * 70)
            print(" MARKDOWN FOR README")
            print("=" * 70)
            print(markdown)

        finally:
            self.cleanup()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run tiny_ca benchmarks")
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of iterations per test (default: 5)",
    )
    args = parser.parse_args()

    benchmark = Benchmark(iterations=args.iterations)
    benchmark.run()


if __name__ == "__main__":
    main()
