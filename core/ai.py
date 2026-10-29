import httpx

from core.config import settings


class AIError(Exception):
    """AI provayder bilan ishlashdagi xatolar."""


class Provider:
    name = "base"

    def chat(self, system: str, messages: list[dict]) -> str:
        """messages: [{"role": "user"|"assistant", "content": "..."}]. Matn qaytaradi."""
        raise NotImplementedError


class OllamaProvider(Provider):
    name = "ollama"

    def chat(self, system: str, messages: list[dict]) -> str:
        try:
            response = httpx.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": [{"role": "system", "content": system}, *messages],
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
                timeout=300,  # lokal model sekin bo'lishi mumkin
            )
        except httpx.ConnectError as e:
            raise AIError("Ollama ishlamayapti (`ollama serve` yoki systemctl status ollama)") from e
        except httpx.HTTPError as e:
            raise AIError(f"Ollama tarmoq xatosi: {e}") from e

        if response.status_code == 404:
            raise AIError(f"Model topilmadi. `ollama pull {settings.ollama_model}` qiling")
        if response.status_code != 200:
            raise AIError(f"Ollama xatosi: HTTP {response.status_code}")
        return response.json()["message"]["content"]


class AnthropicProvider(Provider):
    name = "anthropic"

    def chat(self, system: str, messages: list[dict]) -> str:
        if not settings.anthropic_api_key:
            raise AIError("ANTHROPIC_API_KEY .env faylida topilmadi")
        try:
            response = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": settings.anthropic_model,
                    "max_tokens": 2000,
                    "temperature": 0.2,
                    "system": system,
                    "messages": messages,
                },
                timeout=120,
            )
        except httpx.HTTPError as e:
            raise AIError(f"Anthropic tarmoq xatosi: {e}") from e

        if response.status_code == 401:
            raise AIError("Anthropic API kalit noto'g'ri")
        if response.status_code == 429:
            raise AIError("Anthropic limiti tugagan")
        if response.status_code != 200:
            raise AIError(f"Anthropic xatosi: HTTP {response.status_code} {response.text[:200]}")
        blocks = response.json()["content"]
        return "".join(b["text"] for b in blocks if b["type"] == "text")


PROVIDERS = {"ollama": OllamaProvider, "anthropic": AnthropicProvider}


def get_provider() -> Provider:
    try:
        return PROVIDERS[settings.ai_provider]()
    except KeyError:
        raise AIError(f"Noma'lum AI provayder: '{settings.ai_provider}' (ollama yoki anthropic)")
