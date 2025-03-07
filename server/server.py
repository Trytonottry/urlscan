from fastapi import FastAPI, HTTPException
import requests
import json
import time
from bs4 import BeautifulSoup
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Настройка CORS (если нужно)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API ключи (замените на свои, если требуется)
VIRUSTOTAL_API_KEY = 'c072fd1374f6cb8906b9544736fa8c8e5410a0ac34bdac6f025593d17e95ff37'
URLSCAN_API_KEY = '01956f6a-92ae-7000-862d-1ed43a77e046'

async def check_virustotal(url):
    """Проверка ссылки через VirusTotal."""
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            return f"VirusTotal: {result['positives']} из {result['total']} антивирусов обнаружили угрозы."
        else:
            return "VirusTotal: Угроз не обнаружено."
    return "VirusTotal: Ошибка при проверке."

async def check_urlscan(url):
    """Проверка ссылки через URLScan.io."""
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {'url': url, 'visibility': 'public'}
    
    # Отправка запроса на сканирование
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code != 200:
        return "URLScan.io: Ошибка при отправке запроса на сканирование."
    
    # Получение UUID сканирования
    scan_id = response.json().get('uuid')
    if not scan_id:
        return "URLScan.io: Не удалось получить ID сканирования."
    
    # Ожидание завершения сканирования
    time.sleep(10)  # Можно увеличить время, если сканирование занимает больше времени
    
    # Получение результатов сканирования
    result_response = requests.get(f'https://urlscan.io/api/v1/result/{scan_id}/')
    if result_response.status_code != 200:
        return "URLScan.io: Ошибка при получении результатов сканирования."
    
    result = result_response.json()
    
    # Проверка наличия ключа 'verdicts' в ответе
    if 'verdicts' in result and 'overall' in result['verdicts']:
        if result['verdicts']['overall']['malicious']:
            return "URLScan.io: Обнаружены угрозы."
        else:
            return "URLScan.io: Угроз не обнаружено."
    else:
        return "URLScan.io: Не удалось получить данные о безопасности."

async def check_urlvoid(url):
    """Проверка ссылки через URLVoid (веб-скрейпинг)."""
    try:
        response = requests.get(f'https://www.urlvoid.com/scan/{url}')
        soup = BeautifulSoup(response.text, 'html.parser')
        result = soup.find('div', {'class': 'label-danger'})
        if result:
            return "URLVoid: Обнаружены угрозы."
        else:
            return "URLVoid: Угроз не обнаружено."
    except Exception as e:
        return f"URLVoid: Ошибка при проверке. {str(e)}"

async def check_sucuri(url):
    """Проверка ссылки через Sucuri SiteCheck (веб-скрейпинг)."""
    try:
        response = requests.get(f'https://sitecheck.sucuri.net/results/{url}')
        soup = BeautifulSoup(response.text, 'html.parser')
        result = soup.find('div', {'class': 'scan-result-status'})
        if result and 'Site is clean' not in result.text:
            return "Sucuri: Обнаружены угрозы."
        else:
            return "Sucuri: Угроз не обнаружено."
    except Exception as e:
        return f"Sucuri: Ошибка при проверке. {str(e)}"

@app.get("/check")
async def check_link(url: str):
    """API для проверки ссылки."""
    if not url:
        raise HTTPException(status_code=400, detail="Параметр 'url' отсутствует.")
    
    result = {
        "virustotal": await check_virustotal(url),
        "urlscan": await check_urlscan(url),
        "urlvoid": await check_urlvoid(url),
        "sucuri": await check_sucuri(url),
    }
    
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)