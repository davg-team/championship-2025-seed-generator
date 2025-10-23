package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// GenerateMasterSeedDeterministic создает детерминированный мастер-сид
func GenerateMasterSeedDeterministic(deviceSeeds []string) (string, error) {
	if len(deviceSeeds) == 0 {
		return "", fmt.Errorf("необходим хотя бы один сид устройства")
	}

	// Сортируем для детерминированности
	sortedSeeds := make([]string, len(deviceSeeds))
	copy(sortedSeeds, deviceSeeds)
	sort.Strings(sortedSeeds)

	// Объединяем все сиды
	combined := ""
	for _, seed := range sortedSeeds {
		combined += seed
	}

	// Статичная соль для детерминированности
	salt := []byte("master-seed-salt-v1")

	// PBKDF2 с фиксированными параметрами
	derivedKey := pbkdf2.Key(
		[]byte(combined),
		salt,
		100000,
		64,
		sha512.New,
	)

	// Финальное хэширование
	finalHash := sha512.Sum512(derivedKey)

	return hex.EncodeToString(finalHash[:]), nil
}

func main() {
	fmt.Println("=== Генератор Мастер-Сида ===")
	fmt.Println()
	fmt.Println("Введите сиды от устройств (по одному на строку).")
	fmt.Println("Для завершения ввода оставьте строку пустой и нажмите Enter.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	var deviceSeeds []string
	seedNumber := 1

	for {
		fmt.Printf("Сид #%d: ", seedNumber)

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())

		// Пустая строка - конец ввода
		if input == "" {
			break
		}

		deviceSeeds = append(deviceSeeds, input)
		seedNumber++
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения ввода: %v\n", err)
		os.Exit(1)
	}

	if len(deviceSeeds) == 0 {
		fmt.Println("\n❌ Не введено ни одного сида!")
		os.Exit(1)
	}

	fmt.Printf("\n✓ Получено сидов: %d\n\n", len(deviceSeeds))

	// Генерируем мастер-сид
	masterSeed, err := GenerateMasterSeedDeterministic(deviceSeeds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка генерации: %v\n", err)
		os.Exit(1)
	}

	// Вычисляем SHA-256 хеш для дополнительной информации
	hash := sha512.Sum512([]byte(masterSeed))
	shortHash := hex.EncodeToString(hash[:])[:16]

	// Выводим результат
	fmt.Println("Мастер-сид (детерминированный):")
	fmt.Println(masterSeed)
	fmt.Println()
	fmt.Printf("Длина: %d символа (%d бит энтропии)\n", len(masterSeed), len(masterSeed)*4)
	fmt.Printf("SHA-512 хеш: %s...\n", shortHash)
	fmt.Println()
	fmt.Println("✓ Мастер-сид успешно сгенерирован!")
	fmt.Println()
	fmt.Println("Примечание: при одинаковых входных сидах")
	fmt.Println("всегда будет получаться одинаковый мастер-сид.")
}
