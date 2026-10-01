"""Завдання 1: Модель користувача й облікового запису (ООП в кібербезпеці).

Демонстрація інкапсуляції, наслідування, композиції, @property, @dataclass,
спеціальних методів (__getitem__, __setitem__, __str__) та безпечного хешування паролів.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Додаємо корінь проєкту до sys.path для підтримки запусків з будь-якого каталогу
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Константа ітерацій для PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS: int = 100_000

# Регулярний вираз для валідації email:
# Локальна частина починається з латинської літери, має 3-64 символи з латинських літер,
# цифр або _, далі @ і доменне ім'я з принаймні однією крапкою.
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)


class User:
    """Базовий клас користувача з безпечним хешуванням пароля та валідацією email."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
        password: str | None = None,
    ) -> None:
        """Ініціалізує об'єкт користувача."""
        self.username: str = username
        self.role: str = role
        self.active: bool = active
        self._email: str = ""
        self.email = email  # Валідація через @property setter

        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        """Повертає адресу електронної пошти."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Встановлює та валідує адресу електронної пошти за спрощеним форматом."""
        if not isinstance(value, str):
            raise TypeError("Email must be a string.")
        if not EMAIL_REGEX.match(value):
            raise ValueError(
                f"Некоректний формат email '{value}': локальна частина має починатися "
                "з латинської літери, містити 3–64 символи (літери, цифри, _), а домен — хоча б одну крапку."
            )
        self._email = value

    def set_password(self, password: str) -> None:
        """Встановлює новий пароль з генерацією випадкової солі та PBKDF2-HMAC-SHA256."""
        if not isinstance(password, str) or not password:
            raise ValueError("Password must be a non-empty string.")
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        self.__password_salt = salt
        self.__password_hash = key

    def check_password(self, password: str) -> bool:
        """Безпечно перевіряє пароль за допомогою hmac.compare_digest."""
        if self.__password_hash is None or self.__password_salt is None:
            return False
        candidate_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(candidate_key, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        """Безпечне рядкове представлення без розкриття пароля чи хешу."""
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', active={self.active})"
        )


class Admin(User):
    """Клас адміністратора системи (наслідує User) з керуванням дозволами."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        permissions: set[str] | list[str] | None = None,
        password: str | None = None,
    ) -> None:
        """Ініціалізує адміністратора, уникаючи змінюваних типових аргументів."""
        super().__init__(
            username=username, email=email, role=role, active=active, password=password
        )
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає вказаний дозвіл адміністратору."""
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("Permission must be a non-empty string.")
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        """Відкликає вказаний дозвіл у адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Рядкове представлення адміністратора з переліком дозволів."""
        perms_str = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"active={self.active}, permissions=[{perms_str}])"
        )


class Session:
    """Клас для відстеження безпечної сесії користувача у часовому поясі UTC."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        """Створює об'єкт сесії з мітками часу в UTC."""
        self.ip: str = ip
        now = datetime.now(timezone.utc)
        self.login_time: datetime = login_time if login_time is not None else now
        self.last_activity: datetime = (
            last_activity if last_activity is not None else now
        )

    def touch(self) -> None:
        """Оновлює мітку останньої активності сесії поточним часом UTC."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи активна сесія (час неактивності не перевищує timeout_sec)."""
        if timeout_sec <= 0:
            raise ValueError(
                f"timeout_sec має бути додатним числом, отримано {timeout_sec}"
            )
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        """Рядкове представлення сесії."""
        return (
            f"Session(ip='{self.ip}', login_time={self.login_time.isoformat()}, "
            f"last_activity={self.last_activity.isoformat()})"
        )


@dataclass(frozen=True)
class AuditRecord:
    """Незмінний запис журналу аудиту безпеки."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій автентифікації та дій користувачів."""

    def __init__(self) -> None:
        """Ініціалізує порожній журнал аудиту."""
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> AuditRecord:
        """Фіксує подію в журналі аудиту з часовою міткою UTC (без збереження паролів)."""
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._records.append(record)
        return record

    def show_all(self) -> list[AuditRecord]:
        """Повертає копію списку всіх записів журналу аудиту."""
        return list(self._records)


class UserAccount:
    """Клас облікового запису (композиція User, Session, AuditLog) зі спеціальними методами."""

    SESSION_TIMEOUT_SEC: int = 900  # 15 хвилин таймаут сесії

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Об'єднує користувача, сесію та журнал аудиту (композиція)."""
        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Виконує автентифікацію: перевіряє активність та пароль, створює сесію та логує подію."""
        if (
            not self.user.active
            or self.user.username != username
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        now = datetime.now(timezone.utc)
        self.session = Session(ip=ip, login_time=now, last_activity=now)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевіряє наявність та валідність поточної сесії за таймаутом (невдача не подовжує сеанс)."""
        if self.session is None:
            return False
        return self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує активну сесію та фіксує подію у журналі аудиту."""
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        """Реалізує доступ за ключем до дозволених атрибутів. Захищає хеш та сіль пароля."""
        allowed = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
            "username": self.user.username,
            "email": self.user.email,
            "role": self.user.role,
            "active": self.user.active,
        }
        if key in allowed:
            return allowed[key]
        raise KeyError(f"Доступ до ключа '{key}' заборонено або ключ не існує.")

    def __setitem__(self, key: str, value: Any) -> None:
        """Реалізує оновлення дозволених атрибутів із перевіркою типів."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError(
                    "Значення для 'user' має бути екземпляром класу User або його нащадка."
                )
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути екземпляром Session або None."
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' має бути екземпляром AuditLog."
                )
            self.audit_log = value
        elif key == "email":
            if not isinstance(value, str):
                raise TypeError("Значення для 'email' має бути рядком str.")
            self.user.email = value  # Викличе валідацію @property.setter
        elif key == "active":
            if not isinstance(value, bool):
                raise TypeError("Значення для 'active' має бути типом bool.")
            self.user.active = value
        elif key == "username":
            if not isinstance(value, str):
                raise TypeError("Значення для 'username' має бути рядком str.")
            self.user.username = value
        elif key == "role":
            if not isinstance(value, str):
                raise TypeError("Значення для 'role' має бути рядком str.")
            self.user.role = value
        else:
            raise KeyError(
                f"Зміна атрибута за ключем '{key}' заборонена або ключ невідомий."
            )

    def __str__(self) -> str:
        """Рядкове представлення облікового запису."""
        auth_status = (
            "Authenticated" if self.is_authenticated() else "Not Authenticated"
        )
        return f"UserAccount(user={self.user}, status={auth_status}, logs_count={len(self.audit_log.show_all())})"


def run_task1() -> None:
    """Демонстраційний сценарій для Завдання 1."""
    print("=" * 80)
    print("ЗАВДАННЯ 1: МОДЕЛЬ КОРИСТУВАЧА Й ОБЛІКОВОГО ЗАПИСУ (ООП В КІБЕРБЕЗПЕЦІ)")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 80)

    # 1. Створення звичайного користувача та адміністратора
    print("\n[1] Створення екземплярів User та Admin(User)...")
    user = User(
        username="serg_kulyniak",
        email="serg_kulyniak@cybersec.ua",
        role="operator",
        password="SuperSecretPassword2026!",
    )
    print(f"  [+] Створено об'єкт User: {user}")

    admin = Admin(
        username="sec_admin",
        email="admin_team@cybersec.ua",
        permissions=["read_logs", "manage_users"],
        password="AdminUltraSecureKey2026#",
    )
    print(f"  [+] Створено об'єкт Admin: {admin}")

    # Демонстрація методів Admin
    print("\n[2] Робота з дозволами адміністратора (grant, revoke, has_permission)...")
    admin.grant_permission("export_pii_reports")
    print(f"  [+] Надано дозвіл 'export_pii_reports'. Стан: {admin}")
    print(f"  [?] Чи є дозвіл 'manage_users': {admin.has_permission('manage_users')}")
    print(
        f"  [?] Чи є дозвіл 'delete_database': {admin.has_permission('delete_database')}"
    )
    admin.revoke_permission("read_logs")
    print(f"  [-] Відкликано 'read_logs'. Поточні дозволи: {sorted(admin.permissions)}")

    # 2. Валідація email через @property
    print("\n[3] Перевірка валідації email через @property setter...")
    valid_email = "new_kulyniak@security.net"
    user.email = valid_email
    print(f"  [+] Email успішно змінено на коректний: {user.email}")

    invalid_emails = [
        "12invalid@example.com",  # Починається з цифри
        "me@domain.com",  # Менше ніж 3 символи в локальній частині
        "invalid_email_without_dot@domain",  # Немає крапки в домені
        "user-name@domain.com",  # Містить дефіс у локальній частині (дозволено лише літери, цифри, _)
    ]
    for bad_email in invalid_emails:
        try:
            user.email = bad_email
            print(f"  [!] ПОМИЛКА: Некоректний email '{bad_email}' було прийнято!")
        except ValueError as exc:
            print(f"  [OK] Очікувано перехоплено ValueError для '{bad_email}': {exc}")

    # 3. Композиція в UserAccount та процес автентифікації
    print("\n[4] Автентифікація через UserAccount (User + Session + AuditLog)...")
    account = UserAccount(user=user)
    print(f"  [i] Початковий стан облікового запису: {account}")
    print(f"  [i] Автентифікований до входу: {account.is_authenticated()}")

    # Невдала спроба входу (невірний пароль)
    print("\n  [+] Тест невдалого входу (невірний пароль):")
    auth_fail = account.login("serg_kulyniak", "WrongPassword123", ip="192.168.1.50")
    print(
        f"      Результат входу: {auth_fail}, Автентифікований: {account.is_authenticated()}"
    )

    # Успішний вхід
    print("\n  [+] Тест успішного входу:")
    auth_ok = account.login(
        "serg_kulyniak", "SuperSecretPassword2026!", ip="192.168.1.50"
    )
    print(
        f"      Результат входу: {auth_ok}, Автентифікований: {account.is_authenticated()}"
    )
    print(f"      Поточна сесія: {account.session}")

    # 4. Демонстрація таймауту сесії
    print("\n[5] Перевірка таймауту сесії (Session.is_active)...")
    print(f"  [i] Сесія активна для таймауту 900 сек: {account.session.is_active(900)}")
    # Симуляція таймауту шляхом зміни часу останньої активності назад
    account.session.last_activity = datetime.now(timezone.utc) - timedelta(seconds=905)
    print("  [i] Симуляція: останню активність змінено на 905 секунд назад.")
    print(
        f"  [i] Чи пройшов таймаут (account.is_authenticated()): {account.is_authenticated()}"
    )

    # Повторний успішний вхід для перевірки logout
    account.login("serg_kulyniak", "SuperSecretPassword2026!", ip="192.168.1.50")
    print(
        f"  [+] Сесію відновлено новим входом. Автентифікований: {account.is_authenticated()}"
    )

    # 5. Вихід із системи
    print("\n[6] Вихід із системи (logout)...")
    account.logout()
    print(f"  [+] Виконано logout. Автентифікований: {account.is_authenticated()}")
    print(f"  [+] Сесія після logout: {account.session}")

    # 6. Спеціальні методи __getitem__ та __setitem__
    print("\n[7] Демонстрація спеціальних методів __getitem__ та __setitem__...")
    print(f"  [+] account['username'] : {account['username']}")
    print(f"  [+] account['email']    : {account['email']}")
    print(f"  [+] account['role']     : {account['role']}")
    print(f"  [+] account['active']   : {account['active']}")

    # Зміна атрибута через __setitem__
    account["role"] = "senior_sec_analyst"
    print(f"  [+] Оновлено account['role'] на '{account['role']}'")

    # Спроба доступу до приватних паролів або невідомих ключів
    try:
        _ = account["__password_hash"]
        print("  [!] ПОМИЛКА: Отримано доступ до закритого ключа!")
    except KeyError as exc:
        print(
            f"  [OK] Захист інкапсуляції спрацював: спроба доступу до пароля викликала KeyError: {exc}"
        )

    try:
        account["active"] = "not_a_boolean"
        print("  [!] ПОМИЛКА: Прийнято некоректний тип для 'active'!")
    except TypeError as exc:
        print(
            f"  [OK] Валідація типів спрацювала: присвоєння некоректного типу викликало TypeError: {exc}"
        )

    # 7. Перегляд журналу аудиту AuditLog
    print("\n[8] Всі записи журналу аудиту (AuditLog) з мітками часу UTC:")
    print("-" * 80)
    print(f"{'Час (UTC)':<30} | {'Користувач':<20} | {'Дія':<20}")
    print("-" * 80)
    for rec in account.audit_log.show_all():
        print(
            f"{rec.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'):<30} | {rec.username:<20} | {rec.action:<20}"
        )
    print("-" * 80)
    print("[+] Демонстрація Завдання 1 успішно завершена.\n")


if __name__ == "__main__":
    run_task1()
