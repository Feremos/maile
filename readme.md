# 📬 Maile Raport

Aplikacja webowa FastAPI do zbierania, klasyfikowania i raportowania maili użytkowników.

---

## Funkcje

- Przeglądanie listy maili w przeglądarce
- Dodawanie maili przez endpoint `/webhook`
- Szablony HTML (Jinja2)
- Obsługa plików statycznych
- Baza danych SQLite (SQLAlchemy)

---

## Wymagania

- Python 3.8+
- Plik `requirements.txt` (FastAPI, SQLAlchemy, Jinja2, gunicorn, itp.)

---

## Uruchomienie lokalnie

1. **Zainstaluj zależności:**
    ```
    pip install -r requirements.txt
    ```

2. **Uruchom aplikację:**
    ```
    uvicorn app.main:app --reload
    ```

3. **Otwórz w przeglądarce:**
    ```
    http://127.0.0.1:8000/
    ```

---

## Endpointy

### Strona główna

- `GET /`  
  Wyświetla listę wszystkich maili zapisanych w bazie.

### Webhook

- `POST /webhook`  
  Dodaje nowego maila do bazy.  
  **Body (form-data):**
    - `user_email` (str)
    - `subject` (str)
    - `content` (str)
    - `classification` (str)
    - `suggested_reply` (str)

**Przykład użycia (curl):**
```
curl -X POST https://twoja-aplikacja.onrender.com/webhook \
  -F "user_email=test@example.com" \
  -F "subject=Test" \
  -F "content=To jest test" \
  -F "classification=Test" \
  -F "suggested_reply=Odpowiedz testowa"
```

---

## Struktura katalogów

```
maile-raport/
│
├── app/
│   ├── main.py
│   ├── db.py
│   ├── models.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       └── .gitkeep
├── requirements.txt
└── render.yaml
```

---

## Deploy na Render.com

1. Wrzuć projekt na GitHub.
2. Połącz repozytorium z Render.com.
3. Render automatycznie wykona:
    - `pip install -r requirements.txt`
    - `gunicorn app.main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:10000`
4. Po deployu aplikacja będzie dostępna pod adresem `https://twoja-aplikacja.onrender.com/`.


**Autor:**  
Mateusz Rak
Wiktor Czechowski