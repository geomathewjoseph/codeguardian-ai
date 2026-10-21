"""
CodeGuardian VRAM Monitor
Tracks GPU allocation, peak memory usage, and warns before reaching RTX 5060 8GB limits.
"""

import time
import threading
import torch

class VRAMMonitor:
    def __init__(self, warning_threshold_mb: float = 7200.0, poll_interval: float = 2.0):
        self.device_available = torch.cuda.is_available()
        self.warning_threshold_mb = warning_threshold_mb
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = None
        self.peak_allocated_mb = 0.0
        self.peak_reserved_mb = 0.0

    def get_memory_stats(self):
        if not self.device_available:
            return {"status": "No CUDA device found"}
        
        allocated = torch.cuda.memory_allocated() / (1024 ** 2)
        reserved = torch.cuda.memory_reserved() / (1024 ** 2)
        total = torch.cuda.get_device_properties(0).total_memory / (1024 ** 2)
        free = total - reserved

        self.peak_allocated_mb = max(self.peak_allocated_mb, allocated)
        self.peak_reserved_mb = max(self.peak_reserved_mb, reserved)

        return {
            "device": torch.cuda.get_device_name(0),
            "allocated_mb": round(allocated, 2),
            "reserved_mb": round(reserved, 2),
            "free_mb": round(free, 2),
            "total_mb": round(total, 2),
            "peak_allocated_mb": round(self.peak_allocated_mb, 2),
            "peak_reserved_mb": round(self.peak_reserved_mb, 2)
        }

    def print_summary(self, label: str = "GPU Memory Snapshot"):
        stats = self.get_memory_stats()
        if not self.device_available:
            print(f"[{label}] CUDA not active.")
            return
        
        print("\n" + "="*50)
        print(f" {label} (RTX 5060 Guard)")
        print("="*50)
        print(f" Device:         {stats['device']}")
        print(f" Allocated:      {stats['allocated_mb']} MB")
        print(f" Reserved:       {stats['reserved_mb']} MB")
        print(f" Free VRAM:      {stats['free_mb']} MB / {stats['total_mb']} MB")
        print(f" Peak Allocated: {stats['peak_allocated_mb']} MB")
        print("="*50 + "\n")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            stats = self.get_memory_stats()
            if self.device_available and stats["reserved_mb"] > self.warning_threshold_mb:
                print(f"\n[WARNING: VRAM SPIKE] Reserved: {stats['reserved_mb']} MB / {stats['total_mb']} MB!")
            time.sleep(self.poll_interval)

    def start_background(self):
        if not self.device_available:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop_background(self):
        if self._thread:
            self._stop_event.set()
            self._thread.join(timeout=3)
