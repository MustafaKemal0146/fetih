"""OpenAI provider profile.

Masaüstü kurulum sihirbazı ``openai`` kimliğini sunuyordu, ancak bu kimliğin
CLI tarafında karşılığı yoktu: sağlayıcı ``PROVIDER_REGISTRY`` içinde
bulunmadığı için sihirbazdan OpenAI seçen kullanıcı ilk mesajda
``AuthError: Unknown provider 'openai'`` alıyordu.

Bu profil, diğer OpenAI-uyumlu sağlayıcılarla (deepseek, groq, ...) aynı
``chat_completions`` kipini ve ``OPENAI_API_KEY`` ortam değişkenini kullanır;
kayıt, ``providers`` paketi üzerinden otomatik olarak yapılır.
"""

from providers import register_provider
from providers.base import ProviderProfile

openai = ProviderProfile(
    name="openai",
    display_name="OpenAI",
    env_vars=("OPENAI_API_KEY",),
    base_url="https://api.openai.com/v1",
    signup_url="https://platform.openai.com/api-keys",
)

register_provider(openai)
