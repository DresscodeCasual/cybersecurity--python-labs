"""Завдання 2: Багаторівнева система контролю доступу.

Варіант 13.
"""

import sys
from pathlib import Path

# Додаємо корінь проекту до шляхів пошуку модулів
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def check_access(
    user_login: str,
    resource: tuple[str, int],
    users_dict: dict,
    blocked_set: set[str],
) -> tuple[bool, str]:
    """Перевіряє доступ користувача до ресурсу за алгоритмом розмежування прав.

    Повертає кортеж (чи_надано_доступ, статус_або_причина).
    """
    _resource_name, resource_level = resource

    # 1. Перевірка наявності користувача в системі
    if user_login not in users_dict:
        return False, "User not found"

    # 2. Перевірка перебування у списку заблокованих
    if user_login in blocked_set:
        return False, "User is blocked"

    user_info = users_dict[user_login]

    # 3. Перевірка активності облікового запису
    if not user_info.get("active", False):
        return False, "Account inactive"

    # 4-5. Перевірка рівня допуску (clearance)
    user_clearance = user_info.get("clearance", 0)
    if user_clearance >= resource_level:
        return True, "Access granted"

    return False, "Insufficient clearance"


def run_task2() -> None:
    """Виконує Завдання 2 для варіанту 13."""
    print("=" * 80)
    print("ЗАВДАННЯ 2: Багаторівнева система контролю доступу")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 80)

    # 1. Вхідні дані для варіанту 13
    users = {
        "ai_security_expert": {
            "role": "ai_security",
            "clearance": 4,
            "department": "AI Security",
            "active": True,
        },
        "ml_engineer": {
            "role": "ml_engineer",
            "clearance": 3,
            "department": "Machine Learning",
            "active": True,
        },
        "data_engineer": {
            "role": "data_engineer",
            "clearance": 2,
            "department": "Data Engineering",
            "active": True,
        },
        "research_assistant": {
            "role": "researcher",
            "clearance": 2,
            "department": "Research",
            "active": True,
        },
        "training_bot": {
            "role": "bot_account",
            "clearance": 1,
            "department": "Automation",
            "active": False,
        },
    }

    resources = [
        ("ai_models", 4),
        ("training_datasets", 3),
        ("data_pipelines", 2),
        ("research_notebooks", 2),
        ("model_artifacts", 4),
        ("synthetic_data", 1),
        ("adversarial_tests", 3),
        ("model_registry", 4),
        ("feature_stores", 2),
        ("public_models", 1),
    ]

    security_levels = (
        "Open Source",
        "Internal Research",
        "Proprietary",
        "Trade Secret",
    )

    blocked_users = {"training_bot", "model_theft", "data_poisoning_acc"}

    # 2. Вивід списку ресурсів із текстовими назвами рівнів безпеки
    print("\n[+] Список ресурсів системи (із текстовим рівнем безпеки):")
    for res_name, res_lvl in resources:
        # Рівні від 1 до 4 відповідають індексам від 0 до 3
        lvl_name = security_levels[res_lvl - 1]
        print(f"  - Ресурс: {res_name:<22} | Рівень: {res_lvl} ({lvl_name})")

    # 3-4. Перевірка доступу кожного користувача до кожного ресурсу
    print("\n[+] Результати перевірки доступу для зареєстрованих користувачів:")
    for user_login in users:
        print(f"\n---> Перевірка для користувача: '{user_login}'")
        for res in resources:
            res_name, _ = res
            allowed, reason = check_access(user_login, res, users, blocked_users)
            if allowed:
                print(f"user={user_login} resource={res_name} -> ALLOW")
            else:
                print(f"user={user_login} resource={res_name} -> DENY ({reason})")

    # Додаткові перевірки для демонстрації всіх гілок алгоритму:
    print("\n[+] Демонстрація крайових випадків (невідомий та неактивний користувачі):")
    edge_test_users = [
        (
            "unknown_intruder",
            "Користувач відсутній у базі users",
            resources[0],
        ),
        (
            "model_theft",
            "Користувач у списку blocked_users, але відсутній у users",
            resources[0],
        ),
    ]
    for test_user, desc, test_res in edge_test_users:
        allowed, reason = check_access(test_user, test_res, users, blocked_users)
        status = "ALLOW" if allowed else f"DENY ({reason})"
        print(f"  [{desc}] user={test_user} resource={test_res[0]} -> {status}")


if __name__ == "__main__":
    run_task2()
