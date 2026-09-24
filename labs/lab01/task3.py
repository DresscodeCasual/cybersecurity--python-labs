"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування з винятками.

Варіант 13 (Алгоритм: sha3_256, мінімальна довжина: 14).
"""

import csv
import functools
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

# Додаємо корінь проекту до шляхів пошуку модулів
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Константи для варіанту 13
HASH_ALGORITHM = "sha3_256"
MIN_PASSWORD_LENGTH = 14
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"  # Для варіанту 13 -> "00013"

DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_FILE_PATH = DATA_DIR / "users.csv"
LOG_FILE_PATH = DATA_DIR / "log.json"


class ValidationError(Exception):
    """Виняток валідації паролів за критеріями безпеки."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує hex-хеш від конкатенації пароля та солі за алгоритмом sha3_256."""
    if password is None or password == "":
        raise ValueError("Пароль не може бути порожнім!")
    if salt is None or salt == "":
        raise ValueError("Сіль не може бути порожньою!")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина пароля ({len(password)}) менша за мінімально допустиму "
            f"({MIN_PASSWORD_LENGTH} символів) для варіанту {VARIANT_NUMBER}."
        )

    salted_password = f"{password}{salt}".encode()
    hasher = hashlib.sha3_256(salted_password)
    return hasher.hexdigest()


def log_event(func: Callable) -> Callable:
    """Декоратор для логування спроб авторизації у файл data/log.json."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Визначаємо ім'я користувача з аргументів
        username = "unknown"
        if len(args) > 0 and isinstance(args[0], str):
            username = args[0]
        elif "username" in kwargs:
            username = str(kwargs["username"])

        # З міркувань кібербезпеки маскуємо пароль у журналі аргументів
        sanitized_args = []
        for i, arg in enumerate(args):
            if i == 1:
                sanitized_args.append("********")
            else:
                sanitized_args.append(str(arg))

        sanitized_kwargs = {}
        for k, v in kwargs.items():
            if k == "password":
                sanitized_kwargs[k] = "********"
            elif k == "users_db" and isinstance(v, (list, tuple)):
                sanitized_kwargs[k] = f"<users_db: {len(v)} users>"
            else:
                sanitized_kwargs[k] = str(v)

        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure"
        exception_occurred = None

        try:
            return_val = func(*args, **kwargs)
            if return_val is True:
                result_status = "success"
            else:
                result_status = "failure"
            return return_val
        except (ValueError, ValidationError) as err:
            result_status = "failure"
            exception_occurred = err
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": sanitized_args,
                "kwargs": sanitized_kwargs,
            }
            if exception_occurred is not None:
                log_entry["error"] = str(exception_occurred)

            # Запис у JSON-файл
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                logs_list = []
                if LOG_FILE_PATH.exists() and LOG_FILE_PATH.stat().st_size > 0:
                    try:
                        with open(LOG_FILE_PATH, "r", encoding="utf-8") as jf:
                            loaded = json.load(jf)
                            if isinstance(loaded, list):
                                logs_list = loaded
                    except json.JSONDecodeError:
                        logs_list = []

                logs_list.append(log_entry)
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as jf:
                    json.dump(logs_list, jf, indent=4, ensure_ascii=False)
            except (OSError, FileNotFoundError, PermissionError) as file_err:
                print(
                    f"[!] Помилка запису логів у {LOG_FILE_PATH}: {file_err}",
                    file=sys.stderr,
                )

    return wrapper


def create_user(
    username: str, password: str, salt: str = PERSONAL_SALT
) -> tuple[str, str]:
    """Створює запис користувача з хешованим паролем та сіллю."""
    pwd_hash = generate_hash(password, salt=salt)
    return username, pwd_hash


def create_users(
    users_list: tuple[tuple[str, str], ...] | list[tuple[str, str]],
    salt: str = PERSONAL_SALT,
    target_path: Path = CSV_FILE_PATH,
) -> None:
    """Обробляє список користувачів та зберігає хеші у CSV файл."""
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["username", "password_hash"])
            for login, pwd in users_list:
                user, pwd_hash = create_user(login, pwd, salt=salt)
                writer.writerow([user, pwd_hash])
        print(f"[+] Успішно збережено {len(users_list)} користувачів у {target_path}")
    except (OSError, FileNotFoundError, PermissionError) as err:
        print(f"[!] Помилка введення/виведення при створенні бази CSV: {err}")
        raise


def load_users_db(source_path: Path = CSV_FILE_PATH) -> list[tuple[str, str]]:
    """Зчитує базу користувачів із CSV файлу."""
    users_db: list[tuple[str, str]] = []
    try:
        with open(source_path, "r", newline="", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader, None)
            if header is None:
                return users_db
            for row in reader:
                if len(row) >= 2:
                    users_db.append((row[0], row[1]))
        return users_db
    except FileNotFoundError:
        print(f"[!] Файл бази даних {source_path} не знайдено.")
        raise
    except PermissionError:
        print(f"[!] Відмовлено в доступі до файлу {source_path}.")
        raise
    except OSError as err:
        print(f"[!] Помилка читання файлу {source_path}: {err}")
        raise


def print_users_db(users_db: list[tuple[str, str]]) -> None:
    """Виводить базу користувачів у вигляді структурованої таблиці."""
    print("\n[+] Вміст бази даних користувачів (users.csv):")
    col_w = [4, 18, 66]
    separator = f"+{'-' * col_w[0]}+{'-' * col_w[1]}+{'-' * col_w[2]}+"
    header = (
        f"| {'№':^{col_w[0] - 2}} | {'Логін':<{col_w[1] - 2}} | "
        f"{'Хеш пароля (SHA3-256)':<{col_w[2] - 2}} |"
    )
    print(separator)
    print(header)
    print(separator)
    for i, (login, pwd_hash) in enumerate(users_db, 1):
        print(
            f"| {i:^{col_w[0] - 2}} | {login:<{col_w[1] - 2}} | "
            f"{pwd_hash:<{col_w[2] - 2}} |"
        )
    print(separator)


@log_event
def login(
    username: str,
    password: str,
    users_db: list[tuple[str, str]],
    salt: str = PERSONAL_SALT,
) -> bool:
    """Автентифікує користувача шляхом звірки хешів із бази даних."""
    if not username or username.strip() == "":
        raise ValueError("Ім'я користувача не може бути порожнім!")
    if not password or password == "":
        raise ValueError("Пароль не може бути порожнім!")

    try:
        input_hash = generate_hash(password, salt=salt)
    except ValidationError:
        # Якщо введений пароль не проходить валідацію за довжиною, він апріорі хибний
        return False

    db_dict = dict(users_db)
    if username not in db_dict:
        return False

    stored_hash = db_dict[username]
    return input_hash == stored_hash


def run_task3() -> None:
    """Виконує Завдання 3 для варіанту 13."""
    print("=" * 80)
    print("ЗАВДАННЯ 3: Безпечне хешування, CSV-база та JSON-логування")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print(
        f"Алгоритм: {HASH_ALGORITHM} | Мін. довжина: {MIN_PASSWORD_LENGTH} | Сіль: '{PERSONAL_SALT}'"
    )
    print("=" * 80)

    # Очищення старих файлів у data для чистоти експерименту (якщо є)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if LOG_FILE_PATH.exists():
        LOG_FILE_PATH.unlink()

    # 3. Список користувачів для реєстрації (10 записів, паролі >= 14 символів)
    users_to_register: tuple[tuple[str, str], ...] = (
        ("ai_sec_lead", "Super#Secur3_AI_Master2026"),
        ("ml_researcher", "Neur@l_Net_Prot3ct#99"),
        ("pipeline_admin", "Data_Pip3l1ne_Strong!Pass"),
        ("soc_analyst", "Threat_Hunt1ng_Soc$2026"),
        ("devsecops_eng", "CI_CD_G@tes_Def3nse!123"),
        ("model_auditor", "Audit_Adv3rsarial#Test9"),
        ("cloud_architect", "Cl0ud_S3cure_Infra*2026"),
        ("compliance_mgr", "Compli4nc3_IS027001_Pass!"),
        ("crypto_expert", "Elliptic_Curv3_Crypt0#26"),
        ("incident_resp", "Inc1d3nt_Resp0nse_Team@1"),
    )

    # Демонстрація генерації винятку валідації (короткий пароль)
    print("\n[+] Тестування валідації короткого пароля (< 14 символів):")
    try:
        generate_hash("TooShort#1", salt=PERSONAL_SALT)
    except ValidationError as val_err:
        print(f"  [Очікуваний виняток перехоплено] ValidationError: {val_err}")

    # Демонстрація порожнього пароля або солі
    try:
        generate_hash("", salt=PERSONAL_SALT)
    except ValueError as val_err:
        print(f"  [Очікуваний виняток перехоплено] ValueError: {val_err}")

    # Створення бази користувачів CSV
    print("\n[+] Реєстрація користувачів та збереження у CSV...")
    try:
        create_users(users_to_register, salt=PERSONAL_SALT, target_path=CSV_FILE_PATH)
    except (OSError, FileNotFoundError, PermissionError) as err:
        print(f"[!] Критична помилка збереження: {err}")
        return

    # 4. Читання CSV та структурований вивід
    try:
        users_db = load_users_db(CSV_FILE_PATH)
        print_users_db(users_db)
    except (OSError, FileNotFoundError, PermissionError) as err:
        print(f"[!] Критична помилка завантаження бази: {err}")
        return

    # 5-6. Тестування автентифікації та логування декоратором @log_event
    print("\n[+] Тестування автентифікації через функцію login() (з логуванням):")
    test_cases = [
        ("ai_sec_lead", "Super#Secur3_AI_Master2026", "Коректний вхід"),
        ("ai_sec_lead", "WrongPassword#2026", "Невірний пароль"),
        ("unregistered_user", "ValidLengthP@ssword123", "Неіснуючий користувач"),
        ("ml_researcher", "Neur@l_Net_Prot3ct#99", "Коректний вхід"),
        ("soc_analyst", "Short1!", "Занадто короткий пароль при автентифікації"),
    ]

    for uname, pwd, desc in test_cases:
        try:
            success = login(uname, pwd, users_db=users_db, salt=PERSONAL_SALT)
            status_text = "УСПІХ (ALLOW)" if success else "ВІДМОВА (DENY)"
            print(f"  [{desc}] login('{uname}') -> {status_text}")
        except (ValueError, ValidationError) as err:
            print(f"  [{desc}] login('{uname}') -> Помилка: {err}")

    # Перевірка валідації порожніх аргументів у login
    print("\n[+] Тестування автентифікації з порожнім ім'ям користувача:")
    try:
        login("", "SomePassword12345", users_db=users_db, salt=PERSONAL_SALT)
    except ValueError as err:
        print(f"  [Очікуваний виняток перехоплено] ValueError: {err}")

    # Вивід згенерованого журналу log.json
    print(f"\n[+] Перевірка згенерованого файлу журналу: {LOG_FILE_PATH}")
    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as jf:
            logged_events = json.load(jf)
        print(f"  У журналі зафіксовано подій: {len(logged_events)}")
        print("  Зразок перших двох записів журналу:")
        print(json.dumps(logged_events[:2], indent=4, ensure_ascii=False))
    except (OSError, FileNotFoundError, PermissionError) as err:
        print(f"[!] Помилка читання логу: {err}")


if __name__ == "__main__":
    run_task3()
