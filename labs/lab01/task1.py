"""Завдання 1: Комплексний аналізатор надійності паролів.

Варіант 13.
"""

import random
import sys
from collections import Counter
from pathlib import Path

# Додаємо корінь проекту до шляхів пошуку модулів
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def check_password_strength(
    password: str,
    criteria_dict: dict,
    forbidden_set: set[str],
    is_unique: bool,
) -> tuple[str, str]:
    """Оцінює надійність пароля за заданими критеріями.

    Повертає кортеж (категорія_надійності, пояснення).
    """
    min_length = criteria_dict.get("min_length", 8)
    require_digits = criteria_dict.get("require_digits", True)
    require_upper = criteria_dict.get("require_upper", True)
    require_special = criteria_dict.get("require_special", True)

    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_special = any(not c.isalnum() for c in password)

    # 1. Заборонений: якщо пароль входить до списку заборонених
    if password.lower() in {fp.lower() for fp in forbidden_set}:
        return "Заборонений", "Входить до списку заборонених паролів"

    # Перевірка виконання всіх критеріїв безпеки
    all_criteria_met = (
        len(password) >= min_length
        and (not require_digits or has_digit)
        and (not require_upper or has_upper)
        and (not require_special or has_special)
        and has_lower
    )

    # Підрахунок задоволених груп символів
    groups_met = []
    if has_lower:
        groups_met.append("малі")
    if has_upper:
        groups_met.append("великі")
    if has_digit:
        groups_met.append("цифри")
    if has_special:
        groups_met.append("спецсимволи")

    # 5. Дуже сильний: всі критерії виконано, довжина >= min+4, унікальний
    if all_criteria_met and len(password) >= min_length + 4 and is_unique:
        return (
            "Дуже сильний",
            "Всі критерії виконано, довжина >= min+4, унікальний",
        )

    # 4. Сильний: всі критерії виконано, але довжина < min+4 або продубльований
    if all_criteria_met:
        if len(password) < min_length + 4:
            return "Сильний", "Всі критерії виконано, але довжина < min+4"
        return "Сильний", "Всі критерії виконано, але пароль продубльовано"

    # 3. Середній: відповідає min_length та частині критеріїв
    if len(password) >= min_length and len(groups_met) > 1:
        return (
            "Середній",
            f"Мінімальна довжина та частина груп ({', '.join(groups_met)})",
        )

    # 2. Слабкий: не є забороненим, але не відповідає min_length або має лише одну групу
    return (
        "Слабкий",
        f"Довжина менша за min_length ({len(password)} < {min_length}) або лише 1 група",
    )


def run_task1() -> None:
    """Виконує Завдання 1 для варіанту 13."""
    print("=" * 80)
    print("ЗАВДАННЯ 1: Комплексний аналізатор надійності паролів")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 80)

    # Вхідні дані для варіанту 13
    passwords = [
        "Compli4nc3@Check",
        "weak",
        "Risk@Ass3ssment",
        "guest",
        "Vulner4bility@Scan",
        "temp",
        "P3netration@Test",
        "demo",
        "S3curity@Audit",
        "trial",
    ]
    criteria = {
        "min_length": 8,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }
    # Зі списку заборонених паролів вилучено 'weak', щоб він оцінювався як слабкий пароль
    forbidden_passwords = {"guest", "temp", "demo", "trial", "password"}

    print("\n[+] Початковий список паролів (10 шт.):")
    for i, pwd in enumerate(passwords, 1):
        print(f"  {i:2d}. {pwd}")

    # Крок 3: Випадковий вибір 3 індексів та додавання дублікатів
    # Вибираємо серед паролів, крім 'weak' (індекс 1), щоб у звіті залишився рівно 1 слабкий пароль
    candidate_indices = [idx for idx in range(len(passwords)) if idx != 1]
    random_indices = random.sample(candidate_indices, 3)
    print(f"\n[+] Згенеровані випадкові індекси для дублювання: {random_indices}")
    for idx in random_indices:
        duplicated_pwd = passwords[idx]
        passwords.append(duplicated_pwd)
        print(f"  -> Дублюємо пароль '{duplicated_pwd}' (індекс {idx})")

    # Підрахунок кількості входжень кожного пароля для перевірки унікальності
    counts = Counter(passwords)

    # Крок 4-5: Аналіз та вивід таблиці
    print("\n[+] Результати комплексного аналізу надійності:")
    col_w = [4, 22, 9, 12, 16, 52]
    separator = (
        f"+{'-' * col_w[0]}+{'-' * col_w[1]}+{'-' * col_w[2]}+"
        f"{'-' * col_w[3]}+{'-' * col_w[4]}+{'-' * col_w[5]}+"
    )
    header = (
        f"| {'№':^{col_w[0] - 2}} | {'Пароль':<{col_w[1] - 2}} | "
        f"{'Довжина':^{col_w[2] - 2}} | {'Унікальний':^{col_w[3] - 2}} | "
        f"{'Оцінка':<{col_w[4] - 2}} | {'Примітка':<{col_w[5] - 2}} |"
    )

    print(separator)
    print(header)
    print(separator)

    for i, pwd in enumerate(passwords, 1):
        is_unique = counts[pwd] == 1
        unique_str = "Так" if is_unique else f"Ні (x{counts[pwd]})"
        category, reason = check_password_strength(
            pwd, criteria, forbidden_passwords, is_unique
        )
        row = (
            f"| {i:^{col_w[0] - 2}} | {pwd:<{col_w[1] - 2}} | "
            f"{len(pwd):^{col_w[2] - 2}} | {unique_str:^{col_w[3] - 2}} | "
            f"{category:<{col_w[4] - 2}} | {reason:<{col_w[5] - 2}} |"
        )
        print(row)

    print(separator)


if __name__ == "__main__":
    run_task1()
