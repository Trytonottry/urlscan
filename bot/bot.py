from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import aiohttp
import asyncio

# Токен вашего Telegram-бота
TELEGRAM_BOT_TOKEN = 'ваш_токен_бота'

# URL веб-сервера с API для проверки ссылок
API_URL = "http://ваш_сервер:5000/check"

async def start(update: Update, context):
    """Обработчик команды /start."""
    await update.message.reply_text("Привет! Отправь мне ссылку, и я проверю её на безопасность.")

async def handle_message(update: Update, context):
    """Обработчик текстовых сообщений."""
    url = update.message.text
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(API_URL, params={"url": url}) as response:
                if response.status == 200:
                    result = await response.json()
                    message = (
                        f"Результаты проверки:\n\n"
                        f"{result['virustotal']}\n"
                        f"{result['urlscan']}\n"
                        f"{result['urlvoid']}\n"
                        f"{result['sucuri']}\n"
                    )
                    await update.message.reply_text(message)
                else:
                    await update.message.reply_text("Ошибка при проверке ссылки. Попробуйте позже.")
        except Exception as e:
            await update.message.reply_text(f"Произошла ошибка: {str(e)}")

async def main():
    """Запуск Telegram-бота."""
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Регистрация обработчиков команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Запуск бота
    await application.run_polling()

if __name__ == "__main__":
    asyncio.run(main())