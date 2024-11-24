# **Laboratorium KRYCY: Budowa systemu analizy sieciowej + PoC**

---

## **1. Cel zajęć**
Zadaniem studentów jest stworzenie prototypowego systemu analizy sieciowej w konwencji **Proof of Concept (PoC)**, który:
1. Analizuje dane sieciowe na poziomie flow.
2. Wykorzystuje niektóre zasady **Detection as a Code**.
3. Integruje metody detekcji regułowej i uczenia maszynowego.
4. Wzbogaca dane z użyciem narzędzi Threat Intelligence.
5. Generuje raporty z analizą i wizualizacjami.

Nie wszystkie wymagania muszą zostać w pełni zrealizowane (chodzi o konkretne wymagania, które są podane w tabeli pod koniec instrukcji), ale należy:
- **Zmierzyć się z każdym wymaganiem**,
- Zaproponować **alternatywy** w przypadku trudności.

---

## **2. Wprowadzenie: Detection as a Code**

### **Czym jest Detection as a Code?**

Detection as a Code to nowoczesne podejście, w którym procesy detekcji zagrożeń są wyrażane jako logika programistyczna, zamiast statycznych reguł w narzędziach wykrywania. Dzięki temu możliwa jest dynamiczna analiza i integracja zaawansowanych technik, takich jak przetwarzanie pakietów czy uczenie maszynowe.

Kluczowe cechy:
1. **Automatyzacja**: Reguły detekcyjne mogą być łatwo wdrażane, modyfikowane i testowane w czasie rzeczywistym.
2. **Elastyczność**: Możliwość stosowania reguł napisanych w Pythonie do analizy ruchu sieciowego lub logów.
3. **Integracja z innymi technologiami**: Łączenie logiki detekcyjnej z analizą pakietów, enrichmentem danych, czy modelami uczenia maszynowego.
4. **Programowalność**: Zamiast ograniczać się do sztywnego formatu reguł (np. YAML), można dynamicznie implementować bardziej złożone warunki w Pythonie.

---

### **Przykład: Implementacja Detection as a Code przy użyciu NFStream**

W tym przykładzie analiza odbywa się na poziomie flow z użyciem NFStream, a wykrywanie zagrożeń jest realizowane za pomocą funkcji Python.

```python
from nfstream import NFStreamer

# Definicja funkcji detekcyjnej
def detect_large_flow(flow):
    """
    Wykrywa podejrzanie duży ruch sieciowy wysyłany do konkretnego portu.
    """
    if flow.destination_port == 443 and flow.bytes_sent > 1_000_000:
        return True, f"Suspicious large flow to port 443 from {flow.source_ip}"
    return False, None

# Przetwarzanie pliku PCAP
streamer = NFStreamer(source="sample.pcap")

# Analiza flow
for flow in streamer:
    result, message = detect_large_flow(flow)
    if result:
        print(f"ALERT: {message}")
```

**Wyjaśnienie**:
1. **NFStream**:
   - Biblioteka do analizy ruchu sieciowego na poziomie flow.
   - Pozwala odczytywać statystyki, takie jak liczba przesłanych bajtów, port docelowy czy adres źródłowy.

2. **Funkcja detekcyjna**:
   - Analizuje flow, sprawdzając, czy liczba przesłanych bajtów na port HTTPS (443) przekracza 1 MB.
   - W przypadku wykrycia podejrzanego ruchu generuje alert z odpowiednią informacją.

---

### **Przykład: Detection as a Code przy użyciu scapy**

W tym przykładzie analizujemy ruch na poziomie pakietów za pomocą scapy, sprawdzając określone pola pakietów.

```python
from scapy.all import rdpcap

# Definicja funkcji detekcyjnej
def detect_http_get(packet):
    """
    Wykrywa żądania HTTP GET w pakietach.
    """
    if packet.haslayer("TCP") and packet["TCP"].dport == 80:
        if b"GET" in bytes(packet.payload):
            return True, f"HTTP GET detected from {packet['IP'].src} to {packet['IP'].dst}"
    return False, None

# Wczytanie pliku PCAP
packets = rdpcap("sample.pcap")

# Analiza pakietów
for packet in packets:
    result, message = detect_http_get(packet)
    if result:
        print(f"ALERT: {message}")
```

**Wyjaśnienie**:
1. **Scapy**:
   - Narzędzie do manipulacji i analizy pakietów na poziomie L3/L4.
   - Pozwala na odczytywanie i modyfikowanie pól w pakietach.

2. **Funkcja detekcyjna**:
   - Sprawdza, czy pakiet jest żądaniem HTTP GET na porcie 80 (HTTP).
   - Jeśli tak, generuje alert z informacją o adresie źródłowym i docelowym.

---

### **Dlaczego Detection as a Code?**
- **Programowalność**: Logika oparta na Pythonie pozwala na elastyczność i integrację różnych metod detekcji.
- **Skalowalność**: Możliwość analizowania zarówno pojedynczych pakietów, jak i flow.
- **Praktyczność**: W przeciwieństwie do statycznych formatów, jak Sigma, Python umożliwia dynamiczną analizę w czasie rzeczywistym.


---

## **3. Symulacja ruchu sieciowego**

### **Dlaczego potrzebujemy symulacji ruchu sieciowego?**

Aby udowodnić, że wymagania stawiane systemowi analizy sieciowej są spełnione, potrzebujemy danych, które będą analizowane w naszym narzędziu. Surowe dane w formacie PCAP pozwalają na odtworzenie realistycznych scenariuszy ruchu sieciowego. Symulacja pozwala na:

1. **Testowanie detekcji regułowej**: Na przykład, czy określone wzorce ruchu są poprawnie identyfikowane jako zagrożenia.
2. **Walidację funkcjonalności systemu**: Upewnienie się, że różne komponenty narzędzia, takie jak analiza flow czy enrichment danych, działają poprawnie.
3. **Demonstrację spełnienia wymagań**: Prezentacja działania narzędzia na rzeczywistych lub symulowanych danych.

Symulacje mogą być przeprowadzane przy użyciu:
1. **Odtwarzania ruchu z plików PCAP za pomocą `tcpreplay`**.
2. **Generowania pakietów w czasie rzeczywistym za pomocą `scapy`**.

---

### **Czym jest tcpreplay?**

`tcpreplay` to narzędzie umożliwiające odtwarzanie rzeczywistego ruchu sieciowego z plików PCAP. Dzięki temu można symulować różne scenariusze ruchu w kontrolowanych warunkach laboratoryjnych.

### **Przykład użycia**
1. Pobierz przykładowy plik PCAP:

   - Skorzystaj z zasobu: [https://mcfp.felk.cvut.cz/publicDatasets/](https://mcfp.felk.cvut.cz/publicDatasets/).

Istotne jest to, aby działać na plikach pcap w formacie surowym i przetwarzać je dopiero w tworzonym skrypcie.

2. Odtwórz ruch na wybranym interfejsie:
```
tcpreplay -i eth0 sample.pcap
```
   W powyższym przykładzie:
   - `-i` – określa interfejs, na którym będzie odtwarzany ruch.
   - `sample.pcap` – ścieżka do pliku PCAP.

3. Ogranicz rodzaj odtwarzanego ruchu za pomocą filtru BPF:
```
tcpreplay -i eth0 -F "tcp port 80" sample.pcap
```
   Filtr BPF pozwala symulować wyłącznie wybrany ruch, np. HTTP (`tcp port 80`).

4. Przyspieszanie odtwarzania ruchu:
```
tcpreplay -i eth0 --multiplier=10 sample.pcap
```
   Opcja `--multiplier=10` zwiększa szybkość odtwarzania ruchu dziesięciokrotnie.

5. Zatrzymanie symulacji:
```
Naciśnij `Ctrl+C` w terminalu, aby przerwać symulację w dowolnym momencie.
```

---

### **Generowanie ruchu w czasie rzeczywistym za pomocą scapy**

W niektórych przypadkach możemy nie mieć odpowiedniego pliku PCAP lub potrzebujemy specyficznego ruchu sieciowego, który pasuje do naszych reguł detekcyjnych. W takich sytuacjach `scapy` pozwala na generowanie i wysyłanie pakietów bezpośrednio na interfejs sieciowy.

Przykład: Wysyłanie żądania HTTP GET na port 80.

```python
from scapy.all import IP, TCP, send

# Tworzenie pakietu IP + TCP
packet = IP(dst="192.168.1.10") / TCP(dport=80) / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

# Wysyłanie pakietu
send(packet)

print("Packet sent to 192.168.1.10 on port 80")
```

**Wyjaśnienie**:
1. **IP(dst="192.168.1.10")**: Określa adres docelowy.
2. **TCP(dport=80)**: Określa port docelowy (HTTP).
3. **send(packet)**: Wysyła utworzony pakiet przez domyślny interfejs sieciowy.

---

### **Dlaczego scapy?**
1. **Elastyczność**: Można tworzyć pakiety na poziomie IP, TCP, UDP i wyższych warstw.
2. **Kontrola**: Możliwość precyzyjnego ustawiania pól w pakietach, co jest trudne do osiągnięcia w gotowych plikach PCAP.
3. **Szybkość testów**: Idealne do testowania specyficznych reguł detekcyjnych w czasie rzeczywistym.



## **4. Zadanie: Budowa systemu analizy sieciowej**

### **Cel**
Stwórz system, który:
1. Analizuje flow z plików PCAP (co najmniej NFStream).
2. Wykorzystuje w pewnym stopniu Detection as a Code.
3. Integruje Machine Learning do klasyfikacji ruchu.
4. Wzbogaca dane za pomocą Threat Intelligence (np. reputacja IP, geolokalizacja).
5. Generuje raporty z wynikami analizy, wzbogacone wizualizacjami.

---

| **ID**   | **Kategoria**        | **Opis wymagania**                                                                                      | **Typ**        | **Proponowany sposób udowodnienia/ dodatkowe komentarze**                                                                                             |
|----------|----------------------|---------------------------------------------------------------------------------------------------------|----------------|-----------------------------------------------------------------------------------------------------------|
| **A.1**  | Analiza flow         | Wczytywanie plików PCAP przy użyciu NFStream.                                                            | Must-have      | Implementacja/inne wizualizacje w raporcie z narzędzia.                                                   |
| **A.2**  | Analiza flow         | Dla znalezionych zagrożeń wyświetlanie statystyk flow, takich jak adres źródłowy, adres docelowy, protokół, rozmiar flow. | Must-have      | Musi znajdować się w raporcie generowanym przez narzędzie.                                                |
| **D.1**  | Detection as a Code  | Implementacja reguł detekcyjnych w Pythonie, np. jako funkcje w pliku `detection_rules.py`.              | Must-have      | Napisanie przykładowej reguły i symulacja przy wykorzystaniu tcpreplay lub scapy wywołania alertu.        |
| **D.2**  | Detection as a Code  | Wczytywanie reguł w formacie Sigma z użyciem PySigma.                                                    | Nice-to-have   | Demonstracja wczytywania reguły Sigma, przetwarzania jej w Pythonie i wywołania detekcji zgodnej z tą regułą. |
| **ML.1** | Machine Learning     | Klasyfikacja flow na podstawie cech, takich jak czas trwania, liczba pakietów, protokół (np. z użyciem `scikit-learn`). | Must-have      | Raport generowany przez narzędzie zawiera output z modelu, np. w postaci pewności zwróconej przez model lub wizualizacji działania modelu. |
| **ML.2** | Machine Learning     | Redukcja liczby fałszywych pozytywów (FPR) za pomocą oceny jakości modelu i tuningu hiperparametrów.     | Nice-to-have   | Liczenie metryk takich jak FPR, TPR lub wizualizacja macierzy konfuzji dla testowanego przypadku. |
| **E.1**  | Enrichment           | Pobieranie dodatkowych informacji o IP/domenach, np. z `geopy` lub innych źródeł Threat Intelligence przy użyciu API. | Nice-to-have   | Enrichment widoczny w raporcie generowanym przez narzędzie.                                               |
| **V.1**  | Wizualizacja         | Wykres liczby wykrytych zagrożeń w czasie (np. wykres słupkowy).                                         | Must-have      | Alternatywa: Zamiast wykresów – podsumowanie w tabeli tekstowej lub inna wizualizacja w raporcie z narzędzia. |




### **Uwagi szczególne dotyczące realizacji zadania**
1. **Prototypowanie w Jupyter Notebook**:
   - Jupyter Notebook powinień służyć głównie do prototypowania i testowania poszczególnych modułów (np. funkcji detekcyjnych, modeli ML, wizualizacji).
   - Po opracowaniu działającego prototypu, logika powinna być przenoszona do głównego rozwiązania jako część pełnego systemu.

2. **Interakcja z użytkownikiem**:
   - Warto wykorzystać bibliotekę `click` do stworzenia interaktywnego CLI (Command Line Interface), które umożliwi użytkownikowi wygodne uruchamianie i konfigurację narzędzia.

3. **Wymagania nice to have**:
   - Są to dodatkowe funkcjonalności, które nie są obowiązkowe, ale ich implementacja może dodatkowo podnieść ocenę w przypadku innych braków.
   - Im więcej funkcjonalności, tym lepiej, ale tylko w sytuacji, gdy są one wdrożone poprawnie.

4. **Elastyczność w realizacji wymagań**:
   - Jeśli realizacja jakiegoś wymagania okazuje się trudna lub niepraktyczna, należy zaproponować dobrze uzasadnioną alternatywę.
   - Kluczowym celem jest dojście do konsensusu, tak jak w rzeczywistych projektach, a nie realizacja wymagań za wszelką cenę.

5. **Raport końcowy**:
   - Raport powinien odnosić się do każdego punktu w tabeli wymagań i zawierać dowód realizacji. 
   - Dowody mogą obejmować:
     - Screeny z działania systemu.
     - Wycinki z kodu z objaśnieniami.
     - Wyniki symulacji lub wizualizacje.
   - Raport musi być elegancki i przekonujący, ponieważ to on będzie głównym elementem oceny projektu. Oprócz samego spełnienia każdego z wymagań liczy się styl jego wykazania (np. to czy do symulacji ruchu sieciowego wykorzystano odpowiedni plik pcap). Raport nie musi zawierać innych elementów niż odniesienie się do każdego z wymagań.

6. **Symulacje i testy**:
   - Symulacje mają kluczowe znaczenie dla udowodnienia spełnienia wymagań.
   - Należy wykorzystywać zaprezentowane techniki i narzędzia (np. `scapy`, `tcpreplay` oraz inne z przedstawionych na zajęciach notebooków).
   - Możliwe jest użycie innych narzędzi, które pozwolą spełnić cel.