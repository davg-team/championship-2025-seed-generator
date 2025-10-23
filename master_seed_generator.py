#!/usr/bin/env python3
"""
Генератор мастер-сида для лотерейных систем.
Криптографически стойкий, детерминированный алгоритм на основе PBKDF2-HMAC-SHA512.

Использование:
    python master_seed_generator.py  # Интерактивный режим
    
    # Или в коде:
    from master_seed_generator import generate_master_seed_deterministic
    master_seed = generate_master_seed_deterministic(["seed1", "seed2", "seed3"])
"""

import hashlib
import sys
from typing import List


def generate_master_seed_deterministic(device_seeds: List[str]) -> str:
    """
    Генерирует детерминированный мастер-сид из списка сидов устройств.

    При одинаковых входных данных всегда генерирует одинаковый результат.
    Использует PBKDF2-HMAC-SHA512 с 100,000 итераций для криптографической стойкости.

    Args:
        device_seeds: Список сидов от различных устройств

    Returns:
        Мастер-сид в hex-формате (128 символов, 512 бит энтропии)

    Raises:
        ValueError: Если список сидов пустой

    Example:
        >>> seeds = ["device-alpha-123", "device-beta-456", "device-gamma-789"]
        >>> master_seed = generate_master_seed_deterministic(seeds)
        >>> len(master_seed)
        128
    """
    if not device_seeds:
        raise ValueError("Необходим хотя бы один сид устройства")

    # Шаг 1: Сортируем для детерминированности
    # Порядок ввода не важен - результат всегда одинаковый
    sorted_seeds = sorted(device_seeds)

    # Шаг 2: Объединяем все сиды в одну строку
    combined = ''.join(sorted_seeds)

    # Шаг 3: Используем фиксированную соль для детерминированности
    salt = b"master-seed-salt-v1"

    # Шаг 4: PBKDF2-HMAC-SHA512 с 100,000 итераций
    # Это делает атаку перебором очень медленной (~100ms на попытку)
    derived_key = hashlib.pbkdf2_hmac(
        'sha512',              # Хэш-функция
        combined.encode('utf-8'),  # Пароль (объединенные сиды)
        salt,                  # Соль
        100000,                # Количество итераций
        dklen=64               # Длина выходного ключа (64 байта = 512 бит)
    )

    # Шаг 5: Финальное хэширование для дополнительной диффузии
    final_hash = hashlib.sha512(derived_key).digest()

    # Шаг 6: Конвертируем в hex-строку
    return final_hash.hex()


def interactive_mode():
    """
    Интерактивный режим для генерации мастер-сида.
    Запрашивает сиды у пользователя и генерирует мастер-сид.
    """
    print("=== Генератор Мастер-Сида ===")
    print()
    print("Введите сиды от устройств (по одному на строку).")
    print("Для завершения ввода оставьте строку пустой и нажмите Enter.")
    print()

    device_seeds = []
    seed_number = 1

    while True:
        try:
            user_input = input(f"Сид #{seed_number}: ").strip()

            # Пустая строка - конец ввода
            if not user_input:
                break

            device_seeds.append(user_input)
            seed_number += 1

        except EOFError:
            # Ctrl+D нажат
            print()
            break
        except KeyboardInterrupt:
            # Ctrl+C нажат
            print("\n\n❌ Отменено пользователем")
            sys.exit(1)

    if not device_seeds:
        print("\n❌ Не введено ни одного сида!")
        sys.exit(1)

    print(f"\n✓ Получено сидов: {len(device_seeds)}\n")

    try:
        # Генерируем мастер-сид
        master_seed = generate_master_seed_deterministic(device_seeds)

        # Вычисляем SHA-512 хеш для дополнительной информации
        seed_hash = hashlib.sha512(master_seed.encode('utf-8')).hexdigest()
        short_hash = seed_hash[:16]

        # Выводим результат
        print("Мастер-сид (детерминированный):")
        print(master_seed)
        print()
        print(
            f"Длина: {len(master_seed)} символов ({len(master_seed) * 4} бит энтропии)")
        print(f"SHA-512 хеш: {short_hash}...")
        print()
        print("✓ Мастер-сид успешно сгенерирован!")
        print()
        print("Примечание: при одинаковых входных сидах")
        print("всегда будет получаться одинаковый мастер-сид.")

    except Exception as e:
        print(f"\n❌ Ошибка генерации: {e}", file=sys.stderr)
        sys.exit(1)


def example_usage():
    """Демонстрация использования функции в коде."""
    print("=" * 70)
    print("ПРИМЕР ИСПОЛЬЗОВАНИЯ В КОДЕ")
    print("=" * 70)
    print()

    # Пример 1: Базовое использование
    print("Пример 1: Базовое использование")
    device_seeds = [
        "device-alpha-1234567890",
        "device-beta-9876543210",
        "device-gamma-5555555555"
    ]
    master_seed = generate_master_seed_deterministic(device_seeds)
    print(f"Сиды: {device_seeds}")
    print(f"Мастер-сид: {master_seed}")
    print()

    # Пример 2: Детерминированность (одинаковые сиды)
    print("Пример 2: Детерминированность")
    seeds_v1 = ["abc", "def", "ghi"]
    seeds_v2 = ["ghi", "abc", "def"]  # Другой порядок

    master1 = generate_master_seed_deterministic(seeds_v1)
    master2 = generate_master_seed_deterministic(seeds_v2)

    print(f"Сиды v1: {seeds_v1}")
    print(f"Мастер-сид v1: {master1[:32]}...")
    print()
    print(f"Сиды v2: {seeds_v2}")
    print(f"Мастер-сид v2: {master2[:32]}...")
    print()
    print(f"Одинаковые результаты: {master1 == master2} ✓")
    print()

    # Пример 3: Разные сиды = разные результаты
    print("Пример 3: Разные сиды")
    seeds_a = ["abc", "def", "ghi"]
    seeds_b = ["abc", "def", "xyz"]  # Один сид отличается

    master_a = generate_master_seed_deterministic(seeds_a)
    master_b = generate_master_seed_deterministic(seeds_b)

    print(f"Сиды A: {seeds_a}")
    print(f"Мастер-сид A: {master_a[:32]}...")
    print()
    print(f"Сиды B: {seeds_b}")
    print(f"Мастер-сид B: {master_b[:32]}...")
    print()
    print(f"Разные результаты: {master_a != master_b} ✓")
    print()

    print("=" * 70)


if __name__ == "__main__":
    # Если запущен с аргументом --example, показываем примеры
    if len(sys.argv) > 1 and sys.argv[1] == "--example":
        example_usage()
    else:
        # Иначе запускаем интерактивный режим
        interactive_mode()
