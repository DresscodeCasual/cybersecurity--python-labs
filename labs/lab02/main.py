"""Головний модуль для запуску Лабораторної роботи №2.

Тема: Розробка консольних утиліт для задач кібербезпеки.
Варіант: 13 (Сканер витоків конфіденційних даних / PII Exfiltration Scanner).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Додаємо корінь проєкту до sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labs.lab02.task1 import run_task1
from labs.lab02.task2 import run_scanner
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger("lab02_main")


def print_header() -> None:
    """Виводить уніфікований заголовок лабораторної роботи."""
    print("*" * 80)
    print("НАЦІОНАЛЬНИЙ УНІВЕРСИТЕТ «ЛЬВІВСЬКА ПОЛІТЕХНІКА»")
    print("Кафедра безпеки інформаційних технологій / систем штучного інтелекту")
    print("Лабораторна робота №2: Розробка консольних утиліт для задач кібербезпеки")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група:   {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER} (PII Exfiltration Scanner)")
    print("*" * 80)
    print()


def run_all() -> None:
    """Почергово запускає демонстрацію обох завдань за замовчуванням."""
    print_header()
    print("[>>>] Запуск демонстрації Завдання 1 (ООП: Модель облікового запису)...")
    run_task1()
    print("\n" + "=" * 80 + "\n")
    print("[>>>] Запуск Завдання 2 (CLI-утиліта: Сканер витоків PII)...")
    default_scan_dir = PROJECT_ROOT / "labs" / "lab02" / "data" / "data_v13" / "scan"
    default_out_json = (
        PROJECT_ROOT / "labs" / "lab02" / "data" / "pii_scan_summary.json"
    )
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    run_scanner(
        scan_dir=default_scan_dir,
        patterns="all",
        mask=True,
        out_json=default_out_json,
    )
    print("\n" + "*" * 80)
    print("[+] Всі завдання Лабораторної роботи №2 успішно виконані!")
    print("*" * 80)


def build_parser() -> argparse.ArgumentParser:
    """Створює головний CLI-парсер із підкомандами demo та analyze."""
    parser = argparse.ArgumentParser(
        description="Головна утиліта керування Лабораторною роботою №2.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Команда для виконання")

    # Підкоманда demo
    subparsers.add_parser(
        "demo",
        help="Запустити демонстрацію об'єктно-орієнтованої моделі облікових записів (Завдання 1)",
    )

    # Підкоманда analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Запустити сканер конфіденційних даних PII (Завдання 2)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    default_scan_dir = PROJECT_ROOT / "labs" / "lab02" / "data" / "data_v13" / "scan"
    default_out_json = (
        PROJECT_ROOT / "labs" / "lab02" / "data" / "pii_scan_summary.json"
    )

    analyze_parser.add_argument(
        "--scan-dir",
        type=Path,
        default=default_scan_dir,
        help="Шлях до каталогу для сканування",
    )
    analyze_parser.add_argument(
        "--patterns",
        type=str,
        choices=["all", "cards", "emails"],
        default="all",
        help="Категорії шаблонів для пошуку (all, cards, emails)",
    )
    analyze_parser.add_argument(
        "--mask",
        action="store_true",
        help="Маскувати знайдені дані у JSON-звіті",
    )
    analyze_parser.add_argument(
        "--out-json",
        type=Path,
        default=default_out_json,
        help="Шлях до вихідного JSON-звіту",
    )
    analyze_parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Рівень логування",
    )

    return parser


def main() -> None:
    """Точка входу для виклику модуля."""
    if len(sys.argv) == 1:
        run_all()
        return

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "demo":
        print_header()
        run_task1()
    elif args.command == "analyze":
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
            logger.error("Помилка під час аналізу: %s", exc)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
