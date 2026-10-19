"""One-off storage regex experiment; not an automated test."""
import re

lines = [
    "Buffer I/O error on dev sda1, logical block 11059619, lost async page write",
    "FAT-fs (sda1): Volume was not properly unmounted.",
    "usb 1-12: USB disconnect",
    "device offline error, dev sda, sector 11059651 op 0x1:(WRITE)",
    "SMART overall-health self-assessment test result: FAILED!",
    "BTRFS warning (device nvme0n1p3): read error",
]

storage_rx = re.compile(
    r"SMART overall-health.*FAILED|SMART Health Status:.*(?:BAD|FAILED)|"
    r"critical_warning\s*:\s*[1-9]|medium error|I/O error|BTRFS.*(?:error|corrupt)|"
    r"EXT4-fs error|XFS.*corruption|blk_update_request.*I/O error|"
    r"nvme.*timeout|link down|resetting",
    re.I,
)

for line in lines:
    if storage_rx.search(line):
        dev_match = re.search(r"(?:dev(?:ice)?\s+|FAT-fs\s*\()([a-z0-9]+)\b", line, re.I)
        dev = dev_match.group(1) if dev_match else "unknown"
        print(f"Match: {line} -> dev: {dev}")
