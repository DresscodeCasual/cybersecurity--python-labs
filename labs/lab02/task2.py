"""Завдання 2: Сканер витоків конфіденційних даних (PII Exfiltration Scanner).

Варіант 13: Утиліта для пошуку незахищених персональних даних (PII) у лог-файлах
та текстових документах за допомогою pathlib, re, collections.Counter, argparse та logging.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

# Додаємо корінь проєкту до sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Регулярні вирази для пошуку PII
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD_REGEX = re.compile(r"\b(?:\d{4}[- ]){3}\d{4}\b|\b(?:\d{16})\b")
PHONE_REGEX = re.compile(
    r"(?:\+\d{1,3}[- ](?:\d{1,4}[- ])?\d{2,4}[- ]\d{2,4}[- ]\d{2,4}|\+\d{1,3}[- ]\d{3}[- ]\d{3}[- ]\d{4}|\b0\d{9}\b)"
)
IP_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)

logger = logging.getLogger("pii_scanner")


@dataclass
class PIIMatch:
    """Клас даних для збереження знайденого фрагмента PII."""

    pii_type: str
    raw_value: str
    masked_value: str
    file_path: str
    line_number: int


def mask_credit_card(card: str) -> str:
    """Маскує номер банківської карти за стандартом (наприклад, 4111-****-****-1111)."""
    digits = [c for c in card if c.isdigit()]
    if len(digits) == 16:
        first4 = "".join(digits[:4])
        last4 = "".join(digits[-4:])
        return f"{first4}-****-****-{last4}"
    return "************"


def mask_email(email: str) -> str:
    """Маскує email-адресу (наприклад, u****r@example.com)."""
    if "@" not in email:
        return "******"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[0]}****{local[-1]}@{domain}"


def mask_phone(phone: str) -> str:
    """Маскує номер телефону (наприклад, +1-202-***-**47 або 050****567)."""
    cleaned = phone.strip()
    if len(cleaned) <= 6:
        return "*******"
    if cleaned.startswith("+"):
        prefix_len = 6 if len(cleaned) >= 10 else 4
        return f"{cleaned[:prefix_len]}***-**{cleaned[-2:]}"
    return f"{cleaned[:3]}****{cleaned[-3:]}"


def mask_ip(ip: str) -> str:
    """Маскує хостову частину IPv4-адреси (наприклад, 192.0.2.***)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
    return "***.***.***.***"


def mask_value(pii_type: str, value: str) -> str:
    """Повертає масковане значення відповідно до типу PII."""
    if pii_type == "Credit Card Numbers":
        return mask_credit_card(value)
    if pii_type == "Email Addresses":
        return mask_email(value)
    if pii_type == "Phone Numbers":
        return mask_phone(value)
    if pii_type == "IPv4 Addresses":
        return mask_ip(value)
    return "********"


def get_scan_patterns(pattern_choice: str) -> list[tuple[str, re.Pattern[str]]]:
    """Повертає список категорій та скомпільованих regex для сканування."""
    if pattern_choice == "cards":
        return [("Credit Card Numbers", CARD_REGEX)]
    if pattern_choice == "emails":
        return [("Email Addresses", EMAIL_REGEX)]
    # "all"
    return [
        ("Email Addresses", EMAIL_REGEX),
        ("Credit Card Numbers", CARD_REGEX),
        ("Phone Numbers", PHONE_REGEX),
        ("IPv4 Addresses", IP_REGEX),
    ]


class PIIScanner:
    """Сканер конфіденційних персональних даних (PII) у файловій системі."""

    def __init__(
        self, scan_dir: Path, pattern_choice: str = "all", mask_enabled: bool = False
    ) -> None:
        """Ініціалізує сканер."""
        self.scan_dir: Path = scan_dir
        self.pattern_choice: str = pattern_choice
        self.mask_enabled: bool = mask_enabled
        self.patterns = get_scan_patterns(pattern_choice)
        self.findings: list[PIIMatch] = []
        self.scanned_files_count: int = 0
        self.type_counts: Counter[str] = Counter()

    def scan(self) -> list[PIIMatch]:
        """Рекурсивно сканує каталог за допомогою pathlib.Path та виконує regex-пошук."""
        if not self.scan_dir.exists():
            raise FileNotFoundError(
                f"Каталог для сканування не знайдено: {self.scan_dir}"
            )
        if not self.scan_dir.is_dir():
            raise NotADirectoryError(f"Шлях не є директорією: {self.scan_dir}")

        self.findings.clear()
        self.type_counts.clear()
        self.scanned_files_count = 0

        # Рекурсивний пошук файлів через pathlib.Path.rglob
        files = [p for p in self.scan_dir.rglob("*") if p.is_file()]
        self.scanned_files_count = len(files)

        for file_path in sorted(files):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_number, line in enumerate(f, start=1):
                        for pii_type, regex in self.patterns:
                            matches = regex.findall(line)
                            for raw_val in matches:
                                masked_val = mask_value(pii_type, raw_val)
                                finding = PIIMatch(
                                    pii_type=pii_type,
                                    raw_value=raw_val,
                                    masked_value=masked_val,
                                    file_path=str(file_path.resolve()),
                                    line_number=line_number,
                                )
                                self.findings.append(finding)
                                self.type_counts[pii_type] += 1
            except OSError as err:
                logger.error("Помилка читання файлу %s: %s", file_path, err)

        return self.findings

    def generate_report_dict(self) -> dict:
        """Генерує словник звіту аудиту для серіалізації в JSON."""
        findings_data = []
        for item in self.findings:
            item_dict = asdict(item)
            if self.mask_enabled:
                # У маскованому режимі приховуємо сирі значення
                item_dict["raw_value"] = item_dict["masked_value"]
            findings_data.append(item_dict)

        return {
            "metadata": {
                "student_name": STUDENT_NAME,
                "group_name": GROUP_NAME,
                "variant_number": VARIANT_NUMBER,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "scan_directory": str(self.scan_dir.resolve()),
                "pattern_filter": self.pattern_choice,
                "mask_applied": self.mask_enabled,
                "total_files_scanned": self.scanned_files_count,
                "total_pii_detected": len(self.findings),
            },
            "summary_counts": dict(self.type_counts),
            "findings": findings_data,
        }

    def save_json_report(self, out_path: Path) -> None:
        """Зберігає підсумковий звіт у JSON-файл."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report = self.generate_report_dict()
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)


def run_scanner(
    scan_dir: Path,
    patterns: str = "all",
    mask: bool = False,
    out_json: Path | None = None,
) -> int:
    """Виконує повний цикл сканування та виведення результатів."""
    logger.info("Scanning directory %s for unmasked PII data...", scan_dir)

    scanner = PIIScanner(scan_dir=scan_dir, pattern_choice=patterns, mask_enabled=mask)
    scanner.scan()

    logger.info("Scanned %d files.", scanner.scanned_files_count)

    print("=== Detected Sensitive Data (PII) ===")
    category_order = [
        "Email Addresses",
        "Credit Card Numbers",
        "Phone Numbers",
        "IPv4 Addresses",
    ]
    for cat in category_order:
        if patterns == "cards" and cat != "Credit Card Numbers":
            continue
        if patterns == "emails" and cat != "Email Addresses":
            continue
        matches_count = scanner.type_counts.get(cat, 0)
        print(f"{cat:<20}: {matches_count} matches")

    print("=== Sample Findings (Masked for Display) ===")
    sample_limit = 6
    for finding in scanner.findings[:sample_limit]:
        rel_path = finding.file_path
        try:
            rel_path = str(Path(finding.file_path).relative_to(PROJECT_ROOT))
        except ValueError:
            pass
        print(f"[PII FOUND] File: {rel_path} (Line {finding.line_number})")
        print(f"  {finding.pii_type:<18}: {finding.masked_value}")

    if scanner.findings:
        logger.warning("Unmasked PII found in plaintext logs!")

    if out_json is not None:
        scanner.save_json_report(out_json)
        logger.info("Sanitized report saved to %s", out_json)

    return len(scanner.findings)


def parse_arguments(args: list[str] | None = None) -> argparse.Namespace:
    """Створює парсер аргументів командного рядка."""
    default_scan_dir = PROJECT_ROOT / "labs" / "lab02" / "data" / "data_v13" / "scan"
    default_out_json = (
        PROJECT_ROOT / "labs" / "lab02" / "data" / "pii_scan_summary.json"
    )

    parser = argparse.ArgumentParser(
        description="Сканер витоків конфіденційних даних (PII Exfiltration Scanner) — Лабораторна робота №2, Варіант 13.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--scan-dir",
        type=Path,
        default=default_scan_dir,
        help="Шлях до каталогу для рекурсивного сканування файлів",
    )
    parser.add_argument(
        "--patterns",
        type=str,
        choices=["all", "cards", "emails"],
        default="all",
        help="Категорії конфіденційних даних для пошуку",
    )
    parser.add_argument(
        "--mask",
        action="store_true",
        help="Застосувати маскування чутливих даних у вихідному JSON-звіті",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=default_out_json,
        help="Шлях до файлу для збереження підсумкового аудиторського JSON-звіту",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Рівень логування",
    )
    return parser.parse_args(args)


def main(cli_args: list[str] | None = None) -> None:
    """Точка входу для автономного запуску Завдання 2."""
    args = parse_arguments(cli_args)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="[%(levelname)s] %(message)s",
    )

    try:
        run_scanner(
            scan_dir=args.scan_dir,
            patterns=args.patterns,
            mask=args.mask,
            out_json=args.out_json,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        logger.error("Критична помилка виконання сканування: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
