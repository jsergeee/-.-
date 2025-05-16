import nmap

def scan_host(host, ports="1-1024"):
    """
    Сканиирует указанный хост на указанных портах.

    :param host: IP-адрес или доменное имя
    :param ports: диапазон портов для сканирования
    :return: результат сканирования
    """
    # Создаем экземпляр сканера
    nm = nmap.PortScanner()

    try:
        # Выполняем сканирование
        print(f"Сканирование {host} портов {ports}...")
        nm.scan(host, ports)

        # Обрабатываем результаты
        for proto in nm[host].all_protocols():
            print(f"Протокол: {proto}")
            for port in nm[host][proto]:
                state = nm[host][proto][port]['state']
                print(f"Порт {port}: {state}")

    except nmap.PortScannerError as e:
        print(f"Ошибка при сканировании: {e}")
    except KeyError:
        print("Хост не найден или недоступен.")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    target_host = input("Введите IP-адрес или доменное имя для сканирования: ")
    ports_range = input("Введите диапазон портов (например, 1-1024): ")
    scan_host(target_host, ports_range)
