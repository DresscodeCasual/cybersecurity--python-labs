"""Головний модуль для демонстрації виконання Лабораторної роботи №1.

Тема: Основи розробки на Python, Git та стандарти стилю коду.
Варіант: 13.
"""

import sys
from pathlib import Path

# Додаємо корінь репозиторію до sys.path для підтримки запусків з будь-якої папки
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main() -> None:
    """Головна точка входу для запуску всіх завдань лабораторної роботи."""
    print("*" * 80)
    print("НАЦІОНАЛЬНИЙ УНІВЕРСИТЕТ «ЛЬВІВСЬКА ПОЛІТЕХНІКА»")
    print("Кафедра систем штучного інтелекту / безпеки інформаційних технологій")
    print("Лабораторна робота №1 з дисципліни 'Програмування скриптовими мовами'")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група:   {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("*" * 80)
    print()

    # Запуск Завдання 1
    run_task1()
    print("\n\n")

    # Запуск Завдання 2
    run_task2()
    print("\n\n")

    # Запуск Завдання 3
    run_task3()
    print("\n\n")

    print("*" * 80)
    print("[+] Всі завдання Лабораторної роботи №1 успішно виконані!")
    print("*" * 80)


if __name__ == "__main__":
    main()
